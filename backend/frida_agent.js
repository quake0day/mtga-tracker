// MTGA Mono reflection agent
// Runs inside MTGA.exe via Frida. Resolves mono-2.0-bdwgc.dll exports,
// walks WrapperController.Instance -> Decks/Inventory/Match, sends JSON back.
//
// Protocol (Frida send/recv):
//   recv  {op:"snapshot"}  -> send {type:"snapshot", data:{...}}
//   recv  {op:"ping"}      -> send {type:"pong"}
// The agent also pushes {type:"event", kind:"...", data:{...}} when hooks fire.

'use strict';

// --- Mono API binding -------------------------------------------------------

const MONO_MODULE_NAME = 'mono-2.0-bdwgc.dll';

function getMonoModule() {
  const m = Process.findModuleByName(MONO_MODULE_NAME);
  if (!m) throw new Error(`${MONO_MODULE_NAME} not loaded in target process`);
  return m;
}

const mono = {};

function bindMono() {
  const m = getMonoModule();
  const b = (name, ret, args) =>
    new NativeFunction(m.getExportByName(name), ret, args);

  mono.get_root_domain       = b('mono_get_root_domain', 'pointer', []);
  mono.thread_attach         = b('mono_thread_attach', 'pointer', ['pointer']);
  mono.thread_detach         = b('mono_thread_detach', 'void', ['pointer']);
  mono.domain_assembly_open  = b('mono_domain_assembly_open', 'pointer', ['pointer','pointer']);
  mono.assembly_get_image    = b('mono_assembly_get_image', 'pointer', ['pointer']);
  mono.image_loaded          = b('mono_image_loaded', 'pointer', ['pointer']);
  mono.class_from_name       = b('mono_class_from_name', 'pointer', ['pointer','pointer','pointer']);
  mono.class_get_method_from_name = b('mono_class_get_method_from_name', 'pointer', ['pointer','pointer','int']);
  mono.class_get_field_from_name  = b('mono_class_get_field_from_name',  'pointer', ['pointer','pointer']);
  mono.class_get_property_from_name = b('mono_class_get_property_from_name','pointer', ['pointer','pointer']);
  mono.class_get_name        = b('mono_class_get_name', 'pointer', ['pointer']);
  mono.class_get_namespace   = b('mono_class_get_namespace', 'pointer', ['pointer']);
  mono.class_get_parent      = b('mono_class_get_parent', 'pointer', ['pointer']);
  mono.class_get_fields      = b('mono_class_get_fields', 'pointer', ['pointer','pointer']);
  mono.class_get_methods     = b('mono_class_get_methods', 'pointer', ['pointer','pointer']);
  mono.class_get_properties  = b('mono_class_get_properties', 'pointer', ['pointer','pointer']);
  mono.property_get_name     = b('mono_property_get_name', 'pointer', ['pointer']);
  mono.class_vtable          = b('mono_class_vtable', 'pointer', ['pointer','pointer']);
  mono.runtime_class_init    = b('mono_runtime_class_init', 'void', ['pointer']);
  mono.field_get_name        = b('mono_field_get_name', 'pointer', ['pointer']);
  mono.field_get_type        = b('mono_field_get_type', 'pointer', ['pointer']);
  mono.field_get_value       = b('mono_field_get_value', 'void', ['pointer','pointer','pointer']);
  mono.field_get_value_object= b('mono_field_get_value_object', 'pointer', ['pointer','pointer','pointer']);
  mono.field_static_get_value= b('mono_field_static_get_value', 'void', ['pointer','pointer','pointer']);
  mono.property_get_get_method = b('mono_property_get_get_method', 'pointer', ['pointer']);
  mono.runtime_invoke        = b('mono_runtime_invoke', 'pointer', ['pointer','pointer','pointer','pointer']);
  mono.object_get_class      = b('mono_object_get_class', 'pointer', ['pointer']);
  mono.object_unbox          = b('mono_object_unbox', 'pointer', ['pointer']);
  mono.string_to_utf8        = b('mono_string_to_utf8', 'pointer', ['pointer']);
  mono.free                  = b('mono_free', 'void', ['pointer']);
  // uintptr_t on Windows x64 is 8 bytes; 'ulong' in Frida is 4 bytes on Windows.
  mono.array_length          = b('mono_array_length', 'uint64', ['pointer']);
  mono.array_addr_with_size  = b('mono_array_addr_with_size', 'pointer', ['pointer','int','uint64']);
  mono.array_element_size    = b('mono_array_element_size', 'int', ['pointer']);
  mono.class_get_element_class = b('mono_class_get_element_class', 'pointer', ['pointer']);
  mono.class_is_valuetype    = b('mono_class_is_valuetype', 'int', ['pointer']);
  mono.field_get_offset      = b('mono_field_get_offset', 'uint', ['pointer']);
  mono.compile_method        = b('mono_compile_method', 'pointer', ['pointer']);
  mono.method_get_full_name  = b('mono_method_full_name', 'pointer', ['pointer','int']);
  mono.method_get_name       = b('mono_method_get_name', 'pointer', ['pointer']);
  mono.type_get_name         = b('mono_type_get_name', 'pointer', ['pointer']);
  mono.type_get_class        = b('mono_type_get_class', 'pointer', ['pointer']);
}

// --- helpers ----------------------------------------------------------------

function cstr(ptr) {
  return ptr.isNull() ? null : ptr.readUtf8String();
}

function monoStringToJs(objPtr) {
  if (!objPtr || objPtr.isNull()) return null;
  const utf8 = mono.string_to_utf8(objPtr);
  if (utf8.isNull()) return null;
  const s = utf8.readUtf8String();
  mono.free(utf8);
  return s;
}

function utf8Alloc(s) {
  return Memory.allocUtf8String(s);
}

let rootDomain = null;

function ensureAttached() {
  if (!rootDomain) rootDomain = mono.get_root_domain();
  // mono_thread_attach is idempotent for already-attached threads; Frida may
  // dispatch each recv() on a different worker, so re-attach every time.
  mono.thread_attach(rootDomain);
}

function findImageByAssemblyName(name) {
  // Try mono_image_loaded first (cheap, no file lookup)
  const img = mono.image_loaded(utf8Alloc(name));
  if (!img.isNull()) return img;
  return NULL;
}

function classByName(image, ns, name) {
  const c = mono.class_from_name(image, utf8Alloc(ns), utf8Alloc(name));
  return c.isNull() ? null : c;
}

function classNameOf(klass) {
  if (!klass || klass.isNull()) return null;
  const ns = cstr(mono.class_get_namespace(klass));
  const nm = cstr(mono.class_get_name(klass));
  return (ns && ns.length ? ns + '.' : '') + (nm || '');
}

function propGet(obj, klass, propName) {
  const prop = mono.class_get_property_from_name(klass, utf8Alloc(propName));
  if (prop.isNull()) return null;
  const getter = mono.property_get_get_method(prop);
  if (getter.isNull()) return null;
  const result = mono.runtime_invoke(getter, obj || NULL, NULL, NULL);
  return result.isNull() ? null : result;
}

function methodInvoke(klass, methodName, argc, obj, argsArr) {
  const m = mono.class_get_method_from_name(klass, utf8Alloc(methodName), argc);
  if (m.isNull()) return null;
  const result = mono.runtime_invoke(m, obj || NULL, argsArr || NULL, NULL);
  return result.isNull() ? null : result;
}

function fieldObj(obj, klass, fieldName) {
  const f = mono.class_get_field_from_name(klass, utf8Alloc(fieldName));
  if (f.isNull()) return null;
  const r = mono.field_get_value_object(rootDomain, f, obj || NULL);
  return r.isNull() ? null : r;
}

// Unbox a boxed value-type (uint/int/enum) to a JS number.
// Returns null if obj is null/invalid.
function unboxU32(obj) {
  if (!obj || obj.isNull()) return null;
  const data = mono.object_unbox(obj);
  if (data.isNull()) return null;
  return data.readU32();
}
function unboxI32(obj) {
  if (!obj || obj.isNull()) return null;
  const data = mono.object_unbox(obj);
  if (data.isNull()) return null;
  return data.readS32();
}

// Enumerate all fields on a class via mono_class_get_fields iterator.
// Returns [{name, typeName}].
function enumFields(klass) {
  if (!klass || klass.isNull()) return [];
  const out = [];
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  for (;;) {
    const f = mono.class_get_fields(klass, iter);
    if (f.isNull()) break;
    const name = cstr(mono.field_get_name(f));
    const t = mono.field_get_type(f);
    const tn = t.isNull() ? null : cstr(mono.type_get_name(t));
    out.push({ name, type: tn });
  }
  return out;
}

// Enumerate all properties.
function enumProperties(klass) {
  if (!klass || klass.isNull()) return [];
  const out = [];
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  for (;;) {
    const p = mono.class_get_properties(klass, iter);
    if (p.isNull()) break;
    const name = cstr(mono.property_get_name(p));
    out.push({ name });
  }
  return out;
}

function readUInt32Field(obj, klass, fieldName) {
  const f = mono.class_get_field_from_name(klass, utf8Alloc(fieldName));
  if (f.isNull()) return null;
  const buf = Memory.alloc(4);
  mono.field_get_value(obj, f, buf);
  return buf.readU32();
}

function readStringField(obj, klass, fieldName) {
  const strObj = fieldObj(obj, klass, fieldName);
  return monoStringToJs(strObj);
}

// MonoArray header on x64 (bdwgc Mono used by Unity):
//   MonoObject obj (vtable* + sync*, 16 bytes)
//   mono_array_size_t max_length (uintptr_t, 8 bytes)
//   MonoArrayBounds* bounds (8 bytes, null for 1-dim arrays)
//   -- vector starts here --
const MONO_ARRAY_VECTOR_OFFSET = 32;

// Iterate a System.Collections.Generic.List<T>. Lists have _items (T[]) and
// _size (int32). Correctly handles value-type (struct) element arrays — e.g.
// Client_DeckCard[] stores 8-byte structs inline, not pointers.
function iterateList(listObj, perElement) {
  if (!listObj || listObj.isNull()) return;
  const listKlass = mono.object_get_class(listObj);
  const sizeField = mono.class_get_field_from_name(listKlass, utf8Alloc('_size'));
  const itemsField = mono.class_get_field_from_name(listKlass, utf8Alloc('_items'));
  if (sizeField.isNull() || itemsField.isNull()) return;
  const szBuf = Memory.alloc(4);
  mono.field_get_value(listObj, sizeField, szBuf);
  const size = szBuf.readS32();
  const itemsArr = mono.field_get_value_object(rootDomain, itemsField, listObj);
  if (itemsArr.isNull() || size <= 0) return;
  const arrKlass = mono.object_get_class(itemsArr);
  const elementSize = mono.array_element_size(arrKlass);
  if (elementSize <= 0) return;
  const elementClass = mono.class_get_element_class(arrKlass);
  const isValueType = !elementClass.isNull() && mono.class_is_valuetype(elementClass) !== 0;
  const vectorBase = itemsArr.add(MONO_ARRAY_VECTOR_OFFSET);
  for (let i = 0; i < size; i++) {
    const slot = vectorBase.add(i * elementSize);
    if (isValueType) {
      // Slot IS the struct; pass the address and class to the callback.
      perElement(slot, i, elementClass, true);
    } else {
      // Slot holds a boxed object pointer.
      perElement(slot.readPointer(), i, null, false);
    }
  }
}

// Read every field of a value-type struct located at structAddr. Mono's
// field_get_offset returns the offset within the BOXED representation (which
// has a MonoObject header). For raw inline storage we subtract that header.
const MONO_OBJECT_HEADER_SIZE = 2 * Process.pointerSize;  // vtable + sync = 16 on x64

function serializeValueStruct(structAddr, klass) {
  if (!structAddr || !klass || klass.isNull()) return null;
  const out = { _typeName: classNameOf(klass) };
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  for (;;) {
    const f = mono.class_get_fields(klass, iter);
    if (f.isNull()) break;
    const name = cstr(mono.field_get_name(f));
    if (!name || name.startsWith('<') || name.startsWith('__')) continue;
    const t = mono.field_get_type(f);
    const tn = t.isNull() ? null : cstr(mono.type_get_name(t));
    const boxedOff = mono.field_get_offset(f);
    const off = boxedOff - MONO_OBJECT_HEADER_SIZE;
    if (off < 0) continue;
    try {
      if (tn === 'System.UInt32') out[name] = structAddr.add(off).readU32();
      else if (tn === 'System.Int32') out[name] = structAddr.add(off).readS32();
      else if (tn === 'System.UInt16') out[name] = structAddr.add(off).readU16();
      else if (tn === 'System.UInt8' || tn === 'System.Byte' || tn === 'System.Boolean')
        out[name] = structAddr.add(off).readU8();
      else if (tn === 'System.Int64' || tn === 'System.UInt64')
        out[name] = structAddr.add(off).readU64().valueOf();
      else out[name] = { _type: tn };
    } catch (e) {
      out[name] = { _err: String(e) };
    }
  }
  return out;
}

// Iterate a managed int/uint array ---------------------------------------------
function iterateUIntArray(arrObj, perElement) {
  if (!arrObj || arrObj.isNull()) return;
  const len = mono.array_length(arrObj).valueOf();
  for (let i = 0; i < len; i++) {
    const addr = mono.array_addr_with_size(arrObj, 4, i);
    perElement(addr.readU32(), i);
  }
}

// --- MTGA-specific traversal -------------------------------------------------

let cache = {
  wrapperKlass: null,
  wrapperInstance: null,
  decksManagerKlass: null,
  inventoryManagerKlass: null,
  matchManagerKlass: null,
  deckKlass: null,
};

function getWrapperController() {
  if (cache.wrapperInstance) return cache.wrapperInstance;
  const image = findImageByAssemblyName('Core');
  if (!image) throw new Error('Core assembly not loaded');
  const k = classByName(image, '', 'WrapperController');
  if (!k) throw new Error('WrapperController class not found');
  cache.wrapperKlass = k;
  // Force cctor
  const vt = mono.class_vtable(rootDomain, k);
  mono.runtime_class_init(vt);
  // Call static get_Instance()
  const inst = methodInvoke(k, 'get_Instance', 0, null, null);
  if (!inst) throw new Error('WrapperController.Instance is null (game not fully initialized?)');
  cache.wrapperInstance = inst;
  return inst;
}

// Prefer property getter (triggers lazy init if any), fall back to raw field
// (DecksManager, FormatManager etc. are declared as fields, not properties).
function getManagerVia(wrapperObj, name) {
  const viaProp = propGet(wrapperObj, cache.wrapperKlass, name);
  if (viaProp) return viaProp;
  return fieldObj(wrapperObj, cache.wrapperKlass, name);
}

// Serialize one Client_DeckCard-like object: read every field, convert to a JS
// primitive if the field type is a known primitive, otherwise stringify the
// type name. Works regardless of exact Client_DeckCard shape.
const PRIMITIVE_U32_TYPES = new Set(['System.UInt32', 'System.Int32']);
const PRIMITIVE_U8_TYPES = new Set(['System.Byte', 'System.Boolean']);

function readFieldValue(obj, klass, field, typeName) {
  if (!typeName) return null;
  if (typeName === 'System.String') {
    const s = mono.field_get_value_object(rootDomain, field, obj);
    return monoStringToJs(s);
  }
  if (PRIMITIVE_U32_TYPES.has(typeName)) {
    const buf = Memory.alloc(4);
    mono.field_get_value(obj, field, buf);
    return typeName === 'System.Int32' ? buf.readS32() : buf.readU32();
  }
  if (PRIMITIVE_U8_TYPES.has(typeName)) {
    const buf = Memory.alloc(1);
    mono.field_get_value(obj, field, buf);
    return buf.readU8();
  }
  if (typeName === 'System.UInt64' || typeName === 'System.Int64') {
    const buf = Memory.alloc(8);
    mono.field_get_value(obj, field, buf);
    return typeName === 'System.Int64' ? buf.readS64().toNumber() : buf.readU64().toNumber();
  }
  // Reference type — don't recurse, just note type
  return { _ref: typeName };
}

function serializeSimpleObject(obj) {
  if (!obj || obj.isNull()) return null;
  const klass = mono.object_get_class(obj);
  const out = { _typeName: classNameOf(klass) };
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  for (;;) {
    const f = mono.class_get_fields(klass, iter);
    if (f.isNull()) break;
    const name = cstr(mono.field_get_name(f));
    if (!name || name.startsWith('<')) continue;  // skip <X>k__BackingField, visible via property anyway
    const t = mono.field_get_type(f);
    const tn = t.isNull() ? null : cstr(mono.type_get_name(t));
    try {
      out[name] = readFieldValue(obj, klass, f, tn);
    } catch (e) {
      out[name] = { _err: String(e), _type: tn };
    }
  }
  return out;
}

// Enumerate Dictionary<K,V> where K is an int-sized enum and V is a reference
// type. Walks the internal `entries` array directly — avoids runtime_invoke so
// it works on any Frida worker thread without a full managed callback.
//
// .NET/Mono Dictionary<K,V> entry layout:
//   int32 hashCode  (offset 0)
//   int32 next      (offset 4)
//   K     key       (offset 8, size varies by K)
//   V     value     (after key + alignment)
// Free slots have hashCode == -1. We rely on mono_array_element_size for the
// exact stride, and compute the value offset dynamically: value lives in the
// last `pointer-size` bytes of each entry (V is a reference type here).
function enumerateIntKeyedDict(dictObj, perEntry) {
  if (!dictObj || dictObj.isNull()) return;
  const dk = mono.object_get_class(dictObj);
  let entriesField = mono.class_get_field_from_name(dk, utf8Alloc('_entries'));
  let countField = mono.class_get_field_from_name(dk, utf8Alloc('_count'));
  if (entriesField.isNull()) entriesField = mono.class_get_field_from_name(dk, utf8Alloc('entries'));
  if (countField.isNull()) countField = mono.class_get_field_from_name(dk, utf8Alloc('count'));
  if (entriesField.isNull() || countField.isNull()) return;
  const buf = Memory.alloc(4);
  mono.field_get_value(dictObj, countField, buf);
  const count = buf.readS32();
  const entriesArr = mono.field_get_value_object(rootDomain, entriesField, dictObj);
  if (entriesArr.isNull() || count <= 0) return;
  // Ask Mono for the real element stride instead of guessing.
  const arrKlass = mono.object_get_class(entriesArr);
  const stride = mono.array_element_size(arrKlass);
  if (stride <= 0) return;
  const valueOffset = stride - Process.pointerSize;
  // Expose stride for debugging via a side channel on the dictObj (no-op if no caller consumes it).
  if (globalThis._lastDictMeta) {
    globalThis._lastDictMeta = { count, stride, valueOffset, entriesArrPtr: entriesArr.toString() };
  }
  for (let i = 0; i < count; i++) {
    try {
      const entry = mono.array_addr_with_size(entriesArr, stride, i);
      const hashCode = entry.readS32();
      if (hashCode < 0) continue;
      const keyVal = entry.add(8).readS32();
      const valuePtr = entry.add(valueOffset).readPointer();
      perEntry(keyVal, valuePtr);
    } catch (e) {
      // one bad entry shouldn't kill the whole snapshot
    }
  }
}

// EDeckPile enum (observed on live Client_DeckContents.Piles). Values are the
// usual MTG arena pile codes; we tag names at serialize time.
// Verified via raw entry dump: this live dict used keys 1 and 2. Enum appears
// 1-based. Values are inferred by MTG Arena pile semantics.
const DECK_PILE_NAMES = {
  1: 'MainDeck',
  2: 'Sideboard',
  3: 'Commander',
  4: 'Companion',
  5: 'Attractions',
  6: 'ContrabandExchange',
};

function serializeDeck(deckObj) {
  if (!deckObj || deckObj.isNull()) return null;
  const klass = mono.object_get_class(deckObj);
  const out = {
    _typeName: classNameOf(klass),
    Id: null,
    Name: null,
    DeckTileId: null,
    DeckArtId: null,
    Format: null,
    Description: null,
    Piles: {},
  };
  // Client_Deck exposes Summary (property) and Contents (property)
  const summary = propGet(deckObj, klass, 'Summary') || fieldObj(deckObj, klass, '_summary');
  const contents = propGet(deckObj, klass, 'Contents') || fieldObj(deckObj, klass, '_contents');
  // Id property returns Guid (value type) — stringify via ToString; skip for now
  if (summary && !summary.isNull()) {
    const sk = mono.object_get_class(summary);
    const name = fieldObj(summary, sk, 'Name');
    out.Name = monoStringToJs(name);
    const desc = fieldObj(summary, sk, 'Description');
    out.Description = monoStringToJs(desc);
    // Format etc. live in the Attributes dict; the Client_DeckSummary property
    // getter resolves them. Use the property, not the FORMAT string constant.
    const fmtProp = propGet(summary, sk, 'Format');
    out.Format = monoStringToJs(fmtProp);
    const lastPlayed = propGet(summary, sk, 'LastPlayed');
    out.LastPlayed = monoStringToJs(lastPlayed);
    const isFav = propGet(summary, sk, 'IsFavorite');
    out.IsFavorite = isFav ? monoStringToJs(isFav) : null;
    // DeckTileId/DeckArtId are direct uint32 fields on Client_DeckSummary.
    const tileField = mono.class_get_field_from_name(sk, utf8Alloc('DeckTileId'));
    if (!tileField.isNull()) {
      const b = Memory.alloc(4);
      mono.field_get_value(summary, tileField, b);
      out.DeckTileId = b.readU32();
    }
    const artField = mono.class_get_field_from_name(sk, utf8Alloc('DeckArtId'));
    if (!artField.isNull()) {
      const b = Memory.alloc(4);
      mono.field_get_value(summary, artField, b);
      out.DeckArtId = b.readU32();
    }
  }
  if (contents && !contents.isNull()) {
    const ck = mono.object_get_class(contents);
    const piles = fieldObj(contents, ck, 'Piles');
    if (piles && !piles.isNull()) {
      enumerateIntKeyedDict(piles, (pileKey, list) => {
        const name = DECK_PILE_NAMES[pileKey] || `Pile${pileKey}`;
        const cards = [];
        try {
          iterateList(list, (eltOrPtr, _i, elemClass, isValueType) => {
            const c = isValueType
              ? serializeValueStruct(eltOrPtr, elemClass)
              : serializeSimpleObject(eltOrPtr);
            if (c) cards.push(c);
          });
        } catch (_e) { /* best effort; empty pile stays empty */ }
        out.Piles[name] = cards;
      });
    }
  }
  return out;
}

function snapshotDecks() {
  const wrapper = getWrapperController();
  const decksMgr = getManagerVia(wrapper, 'DecksManager');
  if (!decksMgr) return { error: 'DecksManager is null' };
  const decksMgrKlass = mono.object_get_class(decksMgr);
  cache.decksManagerKlass = decksMgrKlass;
  const list = methodInvoke(decksMgrKlass, 'GetAllCachedDecks', 0, decksMgr, null);
  if (!list) return { decks: [], note: 'GetAllCachedDecks returned null' };
  const decks = [];
  const errors = [];
  iterateList(list, (deckObj, i) => {
    try {
      const d = serializeDeck(deckObj);
      if (d) decks.push(d);
    } catch (e) {
      errors.push({ index: i, error: String(e) });
    }
  });
  return { decks, errors };
}

// Enumerate a Dictionary<uint32, int32> by walking entries directly.
// Entry stride is normally 16 bytes: {int32 hash, int32 next, uint32 key, int32 value}.
function enumerateUIntToIntDict(dictObj, perEntry) {
  if (!dictObj || dictObj.isNull()) return;
  const dk = mono.object_get_class(dictObj);
  // Walk up the class hierarchy to find _entries/_count (CardsAndQuantity
  // inherits Dictionary and declares no fields itself).
  let kcur = dk;
  let entriesField = NULL, countField = NULL;
  while (!kcur.isNull()) {
    const ef = mono.class_get_field_from_name(kcur, utf8Alloc('_entries'));
    const cf = mono.class_get_field_from_name(kcur, utf8Alloc('_count'));
    if (!ef.isNull() && !cf.isNull()) { entriesField = ef; countField = cf; break; }
    kcur = mono.class_get_parent(kcur);
    if (kcur.isNull()) break;
  }
  if (entriesField.isNull() || countField.isNull()) return;
  const buf = Memory.alloc(4);
  mono.field_get_value(dictObj, countField, buf);
  const count = buf.readS32();
  const entriesArr = mono.field_get_value_object(rootDomain, entriesField, dictObj);
  if (entriesArr.isNull() || count <= 0) return;
  const arrKlass = mono.object_get_class(entriesArr);
  const stride = mono.array_element_size(arrKlass);
  if (stride <= 0) return;
  // For Dictionary<uint32, int32>: key at offset 8, value at offset 12.
  const vectorBase = entriesArr.add(MONO_ARRAY_VECTOR_OFFSET);
  for (let i = 0; i < count; i++) {
    try {
      const entry = vectorBase.add(i * stride);
      const hashCode = entry.readS32();
      if (hashCode < 0) continue;
      const key = entry.add(8).readU32();
      const value = entry.add(12).readS32();
      perEntry(key, value);
    } catch (_e) {}
  }
}

function snapshotInventory() {
  const wrapper = getWrapperController();
  const invMgr = getManagerVia(wrapper, 'InventoryManager');
  if (!invMgr) return { error: 'InventoryManager is null' };
  const klass = mono.object_get_class(invMgr);
  const cards = propGet(invMgr, klass, 'Cards');
  if (!cards) return { cards: [], note: 'Cards property null' };
  const cardsKlass = mono.object_get_class(cards);
  // Count field for sanity check
  let total = null;
  {
    let kcur = cardsKlass;
    while (!kcur.isNull()) {
      const cf = mono.class_get_field_from_name(kcur, utf8Alloc('_count'));
      if (!cf.isNull()) {
        const b = Memory.alloc(4);
        mono.field_get_value(cards, cf, b);
        total = b.readS32();
        break;
      }
      kcur = mono.class_get_parent(kcur);
      if (kcur.isNull()) break;
    }
  }
  const owned = [];
  enumerateUIntToIntDict(cards, (grpId, qty) => {
    owned.push({ Id: grpId, Quantity: qty });
  });
  return {
    cardsTypeName: classNameOf(cardsKlass),
    cardCount: total,
    enumeratedCount: owned.length,
    cards: owned,
  };
}

// Rank class enum values (empirical; MTGA ranks)
const RANK_CLASS_NAMES = {
  0: 'None', 1: 'Bronze', 2: 'Silver', 3: 'Gold', 4: 'Platinum', 5: 'Diamond', 6: 'Mythic',
};
// Verified from Wizards.MDN.GreProtobuf.dll via REA.
// Wotc.Mtgo.Gre.External.Messaging.SuperFormat
const FORMAT_NAMES = {
  0: 'None', 1: 'Limited', 2: 'Constructed',
};
// Wotc.Mtgo.Gre.External.Messaging.GameVariant
const VARIANT_NAMES = {
  0: 'None', 1: 'Normal', 2: 'Planechase', 3: 'Vanguard', 4: 'Commander',
  5: 'Archenemy', 6: 'TeamVsTeam', 7: 'TwoHeadedGiant', 8: 'Brawl',
};
// Wotc.Mtgo.Gre.External.Messaging.MatchState
const MATCH_STATE_NAMES = {
  0: 'None', 1: 'GameInProgress', 2: 'GameComplete',
  3: 'MatchComplete', 4: 'Sideboarding',
};

function serializePlayerInfo(pi) {
  if (!pi || pi.isNull()) return null;
  const klass = mono.object_get_class(pi);
  const screenName = fieldObj(pi, klass, '_screenName') || propGet(pi, klass, 'ScreenName');
  const seat = Memory.alloc(4);
  const seatF = mono.class_get_field_from_name(klass, utf8Alloc('SeatId'));
  if (!seatF.isNull()) mono.field_get_value(pi, seatF, seat);
  const team = Memory.alloc(4);
  const teamF = mono.class_get_field_from_name(klass, utf8Alloc('TeamId'));
  if (!teamF.isNull()) mono.field_get_value(pi, teamF, team);
  const rankClass = Memory.alloc(4);
  const rcF = mono.class_get_field_from_name(klass, utf8Alloc('RankingClass'));
  if (!rcF.isNull()) mono.field_get_value(pi, rcF, rankClass);
  const rankTier = Memory.alloc(4);
  const rtF = mono.class_get_field_from_name(klass, utf8Alloc('RankingTier'));
  if (!rtF.isNull()) mono.field_get_value(pi, rtF, rankTier);
  const mythPctBuf = Memory.alloc(4);
  const mpF = mono.class_get_field_from_name(klass, utf8Alloc('MythicPercentile'));
  if (!mpF.isNull()) mono.field_get_value(pi, mpF, mythPctBuf);
  const mythPlace = Memory.alloc(4);
  const mplF = mono.class_get_field_from_name(klass, utf8Alloc('MythicPlacement'));
  if (!mplF.isNull()) mono.field_get_value(pi, mplF, mythPlace);
  // DeckCards and SideboardCards via property to catch backing field variants
  const deckList = propGet(pi, klass, 'DeckCards') || fieldObj(pi, klass, '_deckCards');
  const sbList = propGet(pi, klass, 'SideboardCards') || fieldObj(pi, klass, '_sideboardCards');
  const toUintArr = (listObj) => {
    const arr = [];
    if (listObj && !listObj.isNull()) {
      iterateList(listObj, (slotPtr, _i, _ec, isValueType) => {
        // List<uint32>: element is a 4-byte value type
        if (isValueType) arr.push(slotPtr.readU32());
        else arr.push(slotPtr && !slotPtr.isNull() ? slotPtr.toString() : null);
      });
    }
    return arr;
  };
  return {
    ScreenName: monoStringToJs(screenName),
    SeatId: seat.readU32(),
    TeamId: team.readU32(),
    RankingClass: rankClass.readS32(),
    RankingClassName: RANK_CLASS_NAMES[rankClass.readS32()] || null,
    RankingTier: rankTier.readS32(),
    MythicPercentile: mythPctBuf.readFloat(),
    MythicPlacement: mythPlace.readS32(),
    DeckCards: toUintArr(deckList),
    SideboardCards: toUintArr(sbList),
  };
}

// Verified from Wizards.MDN.GreProtobuf.dll via REA (14 constants):
// Wotc.Mtgo.Gre.External.Messaging.ZoneType
const ZONE_TYPE_NAMES = {
  0: 'None', 1: 'Library', 2: 'Hand', 3: 'Battlefield',
  4: 'Stack', 5: 'Graveyard', 6: 'Exile', 7: 'Command',
  8: 'Revealed', 9: 'Limbo', 10: 'Sideboard', 11: 'Pending',
  12: 'PhasedOut', 13: 'Suppressed',
};
// Phase (not PhaseType) — verified.
const PHASE_NAMES = {
  0: 'None', 1: 'Beginning', 2: 'Main1', 3: 'Combat', 4: 'Main2', 5: 'Ending',
};
// Step (not StepType) — verified.
const STEP_NAMES = {
  0: 'None', 1: 'Untap', 2: 'Upkeep', 3: 'Draw', 4: 'BeginCombat',
  5: 'DeclareAttack', 6: 'DeclareBlock', 7: 'CombatDamage',
  8: 'EndCombat', 9: 'End', 10: 'Cleanup', 11: 'FirstStrikeDamage',
};

function readU32Field(obj, klass, name) {
  const f = mono.class_get_field_from_name(klass, utf8Alloc(name));
  if (f.isNull()) return null;
  const b = Memory.alloc(4);
  mono.field_get_value(obj, f, b);
  return b.readU32();
}
function readS32Field(obj, klass, name) {
  const f = mono.class_get_field_from_name(klass, utf8Alloc(name));
  if (f.isNull()) return null;
  const b = Memory.alloc(4);
  mono.field_get_value(obj, f, b);
  return b.readS32();
}

// Iterate a List<int> directly (int-sized value-type array).
function iterateIntList(listObj, perElement) {
  if (!listObj || listObj.isNull()) return;
  const lk = mono.object_get_class(listObj);
  const szf = mono.class_get_field_from_name(lk, utf8Alloc('_size'));
  const itf = mono.class_get_field_from_name(lk, utf8Alloc('_items'));
  if (szf.isNull() || itf.isNull()) return;
  const b = Memory.alloc(4);
  mono.field_get_value(listObj, szf, b);
  const size = b.readS32();
  const items = mono.field_get_value_object(rootDomain, itf, listObj);
  if (items.isNull() || size <= 0) return;
  const base = items.add(MONO_ARRAY_VECTOR_OFFSET);
  for (let i = 0; i < size; i++) {
    perElement(base.add(i * 4).readS32(), i);
  }
}

// Helpers that try plain field name first, then <Name>k__BackingField fallback.
function fieldU32(obj, klass, name) {
  return readU32Field(obj, klass, name) ?? readU32Field(obj, klass, `<${name}>k__BackingField`);
}
function fieldS32(obj, klass, name) {
  return readS32Field(obj, klass, name) ?? readS32Field(obj, klass, `<${name}>k__BackingField`);
}
function fieldObjPair(obj, klass, name) {
  return fieldObj(obj, klass, name) || fieldObj(obj, klass, `<${name}>k__BackingField`);
}

// Read MtgPlayer.ControllerId (that's the seat id — SystemSeatId is on
// MatchManager.PlayerInfo, not on MtgPlayer).
function readPlayerSeat(playerObj) {
  if (!playerObj || playerObj.isNull()) return null;
  const pk = mono.object_get_class(playerObj);
  return fieldU32(playerObj, pk, 'ControllerId');
}

function serializeZone(zoneObj) {
  if (!zoneObj || zoneObj.isNull()) return null;
  const klass = mono.object_get_class(zoneObj);
  const typeEnum = fieldS32(zoneObj, klass, 'Type');
  const id = fieldU32(zoneObj, klass, 'Id');
  const owner = fieldObjPair(zoneObj, klass, 'Owner');
  const ownerSeat = readPlayerSeat(owner);
  const cardIdsList = fieldObjPair(zoneObj, klass, 'CardIds');
  const cardIds = [];
  iterateIntList(cardIdsList, (v) => cardIds.push(v));
  return {
    Type: typeEnum,
    TypeName: ZONE_TYPE_NAMES[typeEnum] || `Zone${typeEnum}`,
    Id: id,
    OwnerSeatId: ownerSeat,
    CardIds: cardIds,
    Count: cardIds.length,
  };
}

function serializeCardInstance(cardObj) {
  if (!cardObj || cardObj.isNull()) return null;
  const klass = mono.object_get_class(cardObj);
  // BaseGrpId is explicitly a property-backing field.
  const grpId = fieldU32(cardObj, klass, 'BaseGrpId');
  const instanceId = fieldU32(cardObj, klass, 'InstanceId');
  const zoneRef = fieldObjPair(cardObj, klass, 'Zone');
  let zoneType = null;
  if (zoneRef && !zoneRef.isNull()) {
    const zk = mono.object_get_class(zoneRef);
    zoneType = fieldS32(zoneRef, zk, 'Type');
  }
  const controllerRef = fieldObjPair(cardObj, klass, 'Controller');
  const controllerSeat = readPlayerSeat(controllerRef);
  // IsTapped is a bool (1 byte).
  let tapped = null;
  for (const nm of ['IsTapped', '<IsTapped>k__BackingField']) {
    const f = mono.class_get_field_from_name(klass, utf8Alloc(nm));
    if (!f.isNull()) {
      const b = Memory.alloc(1);
      mono.field_get_value(cardObj, f, b);
      tapped = b.readU8() !== 0;
      break;
    }
  }
  return {
    InstanceId: instanceId,
    GrpId: grpId,
    ZoneType: zoneType,
    ZoneTypeName: zoneType != null ? (ZONE_TYPE_NAMES[zoneType] || `Zone${zoneType}`) : null,
    ControllerSeatId: controllerSeat,
    IsTapped: tapped,
  };
}

function serializeMtgPlayer(playerObj) {
  if (!playerObj || playerObj.isNull()) return null;
  const klass = mono.object_get_class(playerObj);
  const out = {
    ControllerId: fieldU32(playerObj, klass, 'ControllerId'),
    LifeTotal: fieldS32(playerObj, klass, 'LifeTotal'),
    StartingLifeTotal: fieldU32(playerObj, klass, 'StartingLifeTotal'),
    MaxHandSize: fieldU32(playerObj, klass, 'MaxHandSize'),
    MulliganCount: fieldU32(playerObj, klass, 'MulliganCount'),
    TimeoutCount: fieldU32(playerObj, klass, 'TimeoutCount'),
    CompanionId: fieldU32(playerObj, klass, 'CompanionId'),
    ControlledByLocalPlayer: null,
    ManaPool: [],
  };
  // ControlledByLocalPlayer is a bool
  const cf = mono.class_get_field_from_name(klass, utf8Alloc('ControlledByLocalPlayer'));
  if (!cf.isNull()) {
    const b = Memory.alloc(1);
    mono.field_get_value(playerObj, cf, b);
    out.ControlledByLocalPlayer = b.readU8() !== 0;
  }
  // ManaPool is a List<Mana> — iterate and collect raw ints for now
  const pool = fieldObjPair(playerObj, klass, 'ManaPool');
  if (pool && !pool.isNull()) {
    iterateList(pool, (eltOrPtr, _i, elemClass, isValueType) => {
      // Each entry is a Mana struct (value type) or ref — just record count
      out.ManaPool.push(1);
    });
  }
  // Counters is on base class MtgEntity. Try to walk the chain.
  let kcur = klass;
  while (!kcur.isNull()) {
    const cf2 = mono.class_get_field_from_name(kcur, utf8Alloc('Counters'));
    if (!cf2.isNull()) {
      const counters = mono.field_get_value_object(rootDomain, cf2, playerObj);
      if (!counters.isNull()) {
        let count = 0;
        iterateList(counters, () => { count++; });
        out.CounterCount = count;
      }
      break;
    }
    kcur = mono.class_get_parent(kcur);
    if (kcur.isNull()) break;
  }
  return out;
}

function snapshotGameState(matchMgr, matchMgrKlass) {
  const greIf = fieldObj(matchMgr, matchMgrKlass, '_greInterface');
  if (!greIf || greIf.isNull()) return null;
  const greKlass = mono.object_get_class(greIf);
  const gameState = fieldObj(greIf, greKlass, '_currentGameState');
  if (!gameState || gameState.isNull()) {
    return { status: '_currentGameState null', mySeatId: readU32Field(greIf, greKlass, '_mySeatId') };
  }
  const gsk = mono.object_get_class(gameState);
  const phase = fieldS32(gameState, gsk, 'CurrentPhase');
  const step = fieldS32(gameState, gsk, 'CurrentStep');
  const out = {
    _typeName: classNameOf(gsk),
    GameStateId: fieldU32(gameState, gsk, 'Id'),
    PrevId: fieldU32(gameState, gsk, 'PrevId'),
    GameWideTurn: fieldU32(gameState, gsk, 'GameWideTurn'),
    CurrentPhase: phase,
    CurrentPhaseName: phase != null ? (PHASE_NAMES[phase] || `Phase${phase}`) : null,
    CurrentStep: step,
    CurrentStepName: step != null ? (STEP_NAMES[step] || `Step${step}`) : null,
    MySeatId: readU32Field(greIf, greKlass, '_mySeatId'),
  };
  for (const key of ['ActivePlayer', 'DecidingPlayer']) {
    const p = fieldObjPair(gameState, gsk, key);
    out[key + 'Seat'] = readPlayerSeat(p);
  }
  // Players list — serialize each MtgPlayer (life, hand size, mana pool etc.)
  const players = fieldObjPair(gameState, gsk, 'Players');
  out.Players = [];
  if (players && !players.isNull()) {
    iterateList(players, (playerObj, _i, _ec, isValueType) => {
      if (!isValueType) {
        const p = serializeMtgPlayer(playerObj);
        if (p) out.Players.push(p);
      }
    });
  }
  const zones = fieldObjPair(gameState, gsk, 'Zones');
  out.Zones = [];
  if (zones && !zones.isNull()) {
    iterateList(zones, (zoneObj, _i, _ec, isValueType) => {
      if (!isValueType) {
        const z = serializeZone(zoneObj);
        if (z) out.Zones.push(z);
      }
    });
  }
  const cards = fieldObjPair(gameState, gsk, 'VisibleCards') || fieldObjPair(gameState, gsk, 'AllCards');
  out.Cards = [];
  if (cards && !cards.isNull()) {
    iterateList(cards, (cardObj, _i, _ec, isValueType) => {
      if (!isValueType) {
        const c = serializeCardInstance(cardObj);
        if (c) out.Cards.push(c);
      }
    });
  }
  return out;
}

// MatchScope enum (Wotc.Mtgo.Gre.External.Messaging.MatchScope, inferred)
// 0=Unknown 1=Game 2=Match (verified: Game result rows appear first in list, Match row last)
const MATCH_SCOPE_NAMES = { 0: 'Unknown', 1: 'Game', 2: 'Match' };
// ResultType enum (inferred from standard MTG conventions)
const RESULT_TYPE_NAMES = { 0: 'None', 1: 'Victory', 2: 'Defeat', 3: 'Draw' };

function serializeGameResults(matchMgr, klass) {
  const list = propGet(matchMgr, klass, 'GameResults') || fieldObj(matchMgr, klass, '<GameResults>k__BackingField');
  if (!list || list.isNull()) return [];
  const out = [];
  iterateList(list, (slotAddr, _i, elemClass, isValueType) => {
    if (!isValueType || !elemClass || elemClass.isNull()) return;
    // GameResult struct: Result(int), Winner(int), Reason(int), Scope(int), WinnerId(uint32)
    // Boxed offsets - 16 header. Fields are all 4-byte at consecutive offsets.
    const fields = {};
    const iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(NULL);
    for (;;) {
      const f = mono.class_get_fields(elemClass, iter);
      if (f.isNull()) break;
      const name = cstr(mono.field_get_name(f));
      if (!name || name.startsWith('<') || name.startsWith('__')) continue;
      const t = mono.field_get_type(f);
      const tn = t.isNull() ? null : cstr(mono.type_get_name(t));
      const off = mono.field_get_offset(f) - MONO_OBJECT_HEADER_SIZE;
      if (off < 0) continue;
      if (tn === 'System.UInt32') fields[name] = slotAddr.add(off).readU32();
      else fields[name] = slotAddr.add(off).readS32();
    }
    out.push({
      Result: fields.Result,
      ResultName: RESULT_TYPE_NAMES[fields.Result] || `Result${fields.Result}`,
      Winner: fields.Winner,
      Reason: fields.Reason,
      Scope: fields.Scope,
      ScopeName: MATCH_SCOPE_NAMES[fields.Scope] || `Scope${fields.Scope}`,
      WinnerId: fields.WinnerId,
    });
  });
  return out;
}

function snapshotMatch() {
  const wrapper = getWrapperController();
  const matchMgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
  if (!matchMgr) return { active: false, note: '_matchManager null (no live match)' };
  const klass = mono.object_get_class(matchMgr);
  const out = { active: true, _typeName: classNameOf(klass) };
  const matchId = propGet(matchMgr, klass, 'MatchID');
  out.MatchID = monoStringToJs(matchId) || null;
  out.LocalPlayerSeatId = unboxU32(propGet(matchMgr, klass, 'LocalPlayerSeatId'));
  out.CurrentGameNumber = unboxU32(propGet(matchMgr, klass, 'CurrentGameNumber'));
  const fmt = unboxU32(propGet(matchMgr, klass, 'Format'));
  out.Format = fmt;
  out.FormatName = fmt != null ? (FORMAT_NAMES[fmt] || `Format${fmt}`) : null;
  const variant = unboxU32(propGet(matchMgr, klass, 'Variant'));
  out.Variant = variant;
  out.VariantName = variant != null ? (VARIANT_NAMES[variant] || `Variant${variant}`) : null;
  const ms = unboxU32(propGet(matchMgr, klass, 'MatchState'));
  out.MatchState = ms;
  out.MatchStateName = ms != null ? (MATCH_STATE_NAMES[ms] || `State${ms}`) : null;
  const bf = propGet(matchMgr, klass, 'BattlefieldId');
  out.BattlefieldId = monoStringToJs(bf) || null;
  // Flags
  const practice = unboxU32(propGet(matchMgr, klass, 'IsPracticeGame'));
  out.IsPracticeGame = practice === 1;
  const priv = unboxU32(propGet(matchMgr, klass, 'IsPrivateGame'));
  out.IsPrivateGame = priv === 1;
  // Player info
  out.LocalPlayer = serializePlayerInfo(propGet(matchMgr, klass, 'LocalPlayerInfo'));
  out.Opponent = serializePlayerInfo(propGet(matchMgr, klass, 'OpponentInfo'));
  out.GameResults = serializeGameResults(matchMgr, klass);
  out.GameState = snapshotGameState(matchMgr, klass);
  return out;
}

function fullSnapshot() {
  ensureAttached();
  const out = { ts: Date.now() };
  try { out.decks = snapshotDecks(); } catch (e) { out.decks = { error: String(e) }; }
  try { out.inventory = snapshotInventory(); } catch (e) { out.inventory = { error: String(e) }; }
  try { out.match = snapshotMatch(); } catch (e) { out.match = { error: String(e) }; }
  return out;
}

// --- RPC entry --------------------------------------------------------------

function init() {
  bindMono();
  rootDomain = mono.get_root_domain();
  send({ type: 'ready', mono: MONO_MODULE_NAME, rootDomain: rootDomain.toString() });
}

// --- Event hooks (replace polling with push-on-change) ------------------------
//
// Approach: find key MatchManager setters/action-invokers, JIT-compile them if
// not already compiled, Interceptor.attach the native entry point, send an
// event message when they fire. Each hook does zero managed work in onEnter
// (just sends a Frida message); the Python side requests a fresh snapshot in
// response to events it cares about.

const installedHooks = {};  // name -> { nativePtr, listener }

function compileAndHook(klass, methodName, argc, label) {
  if (installedHooks[label]) return { already: true };
  const m = mono.class_get_method_from_name(klass, utf8Alloc(methodName), argc);
  if (m.isNull()) return { error: `method ${methodName}(${argc}) not found on class` };
  const native = mono.compile_method(m);
  if (native.isNull()) return { error: `compile_method returned null for ${methodName}` };
  const listener = Interceptor.attach(native, {
    onEnter(args) {
      // args[0] is 'this' for instance methods; args[1..] are params.
      // For setter(value_type), args[1] holds the raw value for small types.
      let payload = null;
      try {
        if (argc >= 1) payload = args[1].toInt32();
      } catch (_e) {}
      send({ type: 'event', kind: label, payload });
    }
  });
  installedHooks[label] = { native, listener };
  return { installed: true, nativePtr: native.toString() };
}

// Find a class across all loaded assemblies by scanning likely ones.
function findClassAnywhere(ns, name) {
  const assemblies = ['Core', 'SharedClientCore', 'Assembly-CSharp', 'Wizards.MDN.GreProtobuf'];
  for (const asm of assemblies) {
    const img = mono.image_loaded(utf8Alloc(asm));
    if (img.isNull()) continue;
    const k = mono.class_from_name(img, utf8Alloc(ns), utf8Alloc(name));
    if (!k.isNull()) return { klass: k, image: asm };
  }
  return null;
}

function dumpClassMethods(klass) {
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  const methods = [];
  for (;;) {
    const m = mono.class_get_methods(klass, iter);
    if (m.isNull()) break;
    methods.push(cstr(mono.method_get_name(m)) || '?');
  }
  return methods;
}

function installGreHooks() {
  ensureAttached();
  const results = {};
  // MessageHistory: Track* methods fire on every GRE message
  const mh = findClassAnywhere('GreClient.History', 'MessageHistory');
  if (mh) {
    results.MessageHistory = { image: mh.image, methods: dumpClassMethods(mh.klass).slice(0, 30) };
    for (const [methodName, label] of [
      ['TrackIncoming', 'GreIncoming'],
      ['TrackOutgoing', 'GreOutgoing'],
      ['OnGameStateParsed', 'GreGameStateParsed'],
    ]) {
      // -1 lets Mono match any arity (we don't actually care about arg types)
      const r = compileAndHook(mh.klass, methodName, -1, label);
      results[`MH_${methodName}`] = r;
    }
  } else {
    results.MessageHistory = { error: 'class not found' };
  }
  // GreInterface: ParseFullGameStateMessage runs on every full-state update
  const gi = findClassAnywhere('GreClient.Rules', 'GreInterface');
  if (gi) {
    results.GreInterface = { image: gi.image, methods: dumpClassMethods(gi.klass).slice(0, 30) };
    for (const [methodName, argc, label] of [
      ['ParseFullGameStateMessage', 1, 'GreFullState'],
      ['OnMessageReceived', 1, 'GreOnMsg'],
      ['GetZoneUpdates', 1, 'GreZoneUpdates'],
    ]) {
      const r = compileAndHook(gi.klass, methodName, argc, label);
      if (r.installed) results[`GI_${methodName}`] = r;
    }
  } else {
    results.GreInterface = { error: 'class not found' };
  }
  return results;
}

function installMatchHooks() {
  ensureAttached();
  const wrapper = getWrapperController();
  const matchMgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
  if (!matchMgr) return { error: '_matchManager null' };
  const klass = mono.object_get_class(matchMgr);
  const results = {};
  results.set_MatchState = compileAndHook(klass, 'set_MatchState', 1, 'MatchState');
  results.set_MatchID = compileAndHook(klass, 'set_MatchID', 1, 'MatchID');
  results.set_CurrentGameNumber = compileAndHook(klass, 'set_CurrentGameNumber', 1, 'GameNumber');
  results.set_LocalPlayerSeatId = compileAndHook(klass, 'set_LocalPlayerSeatId', 1, 'LocalPlayerSeat');
  return results;
}

function dumpWrapper() {
  ensureAttached();
  const wrapper = getWrapperController();
  const klass = cache.wrapperKlass;
  return {
    typeName: classNameOf(klass),
    fields: enumFields(klass),
    properties: enumProperties(klass),
  };
}

function dumpType(obj) {
  if (!obj || obj.isNull()) return null;
  const klass = mono.object_get_class(obj);
  return {
    typeName: classNameOf(klass),
    fields: enumFields(klass),
    properties: enumProperties(klass),
  };
}

function dumpManagerByProp(name) {
  ensureAttached();
  const wrapper = getWrapperController();
  const mgr = getManagerVia(wrapper, name);
  if (!mgr) return { error: `property/field ${name} returned null` };
  return dumpType(mgr);
}

function onMessage(msg) {
  try {
    if (msg.op === 'ping') return send({ type: 'pong', ts: Date.now() });
    if (msg.op === 'snapshot') {
      const snap = fullSnapshot();
      return send({ type: 'snapshot', id: msg.id || null, data: snap });
    }
    if (msg.op === 'install_hooks') {
      return send({ type: 'install_hooks', id: msg.id || null, data: installMatchHooks() });
    }
    if (msg.op === 'install_gre_hooks') {
      return send({ type: 'install_gre_hooks', id: msg.id || null, data: installGreHooks() });
    }
    if (msg.op === 'dump_wrapper') {
      return send({ type: 'dump_wrapper', id: msg.id || null, data: dumpWrapper() });
    }
    if (msg.op === 'dump_manager') {
      return send({ type: 'dump_manager', id: msg.id || null, name: msg.name, data: dumpManagerByProp(msg.name) });
    }
    if (msg.op === 'dump_first_deck') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      if (!decksMgr) return send({ type: 'dump_first_deck', id: msg.id || null, data: { error: 'DecksManager null' } });
      const decksMgrKlass = mono.object_get_class(decksMgr);
      cache.decksManagerKlass = decksMgrKlass;
      const list = methodInvoke(decksMgrKlass, 'GetAllCachedDecks', 0, decksMgr, null);
      if (!list) return send({ type: 'dump_first_deck', id: msg.id || null, data: { error: 'GetAllCachedDecks null' } });
      let first = null;
      iterateList(list, (deckObj, i) => { if (i === 0) first = deckObj; });
      if (!first) return send({ type: 'dump_first_deck', id: msg.id || null, data: { error: 'list empty' } });
      return send({ type: 'dump_first_deck', id: msg.id || null, data: dumpType(first) });
    }
    if (msg.op === 'dump_gre_interface') {
      ensureAttached();
      const wrapper = getWrapperController();
      const mgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
      if (!mgr) return send({ type: 'dump_gre_interface', id: msg.id || null, data: { error: 'match null' } });
      const klass = mono.object_get_class(mgr);
      const greIf = fieldObj(mgr, klass, '_greInterface');
      if (!greIf || greIf.isNull()) return send({ type: 'dump_gre_interface', id: msg.id || null, data: { status: '_greInterface null' } });
      const gk = mono.object_get_class(greIf);
      return send({ type: 'dump_gre_interface', id: msg.id || null, data: {
        typeName: classNameOf(gk),
        fields: enumFields(gk),
        properties: enumProperties(gk),
      }});
    }
    if (msg.op === 'dump_inventory_cards') {
      ensureAttached();
      const wrapper = getWrapperController();
      const invMgr = getManagerVia(wrapper, 'InventoryManager');
      if (!invMgr) return send({ type: 'dump_inventory_cards', id: msg.id || null, data: { error: 'InventoryManager null' } });
      const klass = mono.object_get_class(invMgr);
      const cards = propGet(invMgr, klass, 'Cards');
      if (!cards || cards.isNull()) return send({ type: 'dump_inventory_cards', id: msg.id || null, data: { error: 'Cards null' } });
      const cardsKlass = mono.object_get_class(cards);
      // Dump methods too to find a getter / iterator
      const iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(NULL);
      const methods = [];
      for (;;) {
        const m = mono.class_get_methods(cardsKlass, iter);
        if (m.isNull()) break;
        methods.push(cstr(mono.method_get_name(m)) || '?');
      }
      return send({ type: 'dump_inventory_cards', id: msg.id || null, data: {
        typeName: classNameOf(cardsKlass),
        fields: enumFields(cardsKlass),
        properties: enumProperties(cardsKlass),
        methods: methods.slice(0, 40),
      }});
    }
    if (msg.op === 'dump_message_history') {
      ensureAttached();
      const wrapper = getWrapperController();
      const mgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
      if (!mgr) return send({ type: 'dump_message_history', id: msg.id || null, data: { error: 'match null' } });
      const klass = mono.object_get_class(mgr);
      const history = propGet(mgr, klass, 'MessageHistory') || fieldObj(mgr, klass, '<MessageHistory>k__BackingField');
      if (!history || history.isNull()) return send({ type: 'dump_message_history', id: msg.id || null, data: { status: 'null' } });
      const hk = mono.object_get_class(history);
      // Enumerate class methods too
      const methodsIter = Memory.alloc(Process.pointerSize);
      methodsIter.writePointer(NULL);
      const methods = [];
      for (;;) {
        const m = mono.class_get_methods(hk, methodsIter);
        if (m.isNull()) break;
        const n = cstr(mono.method_get_name(m));
        if (n) methods.push(n);
      }
      return send({ type: 'dump_message_history', id: msg.id || null, data: {
        typeName: classNameOf(hk),
        fields: enumFields(hk),
        properties: enumProperties(hk),
        methods: methods.slice(0, 50),
      }});
    }
    if (msg.op === 'dump_game_result_type') {
      ensureAttached();
      // GameResult is a nested type on MatchManager — try to find it.
      const img = mono.image_loaded(utf8Alloc('Core'));
      if (img.isNull()) return send({ type: 'dump_game_result_type', id: msg.id || null, data: { error: 'Core not loaded' } });
      // Nested types: name is "MatchManager/GameResult" in metadata; mono_class_from_name uses /
      let k = mono.class_from_name(img, utf8Alloc(''), utf8Alloc('MatchManager/GameResult'));
      if (k.isNull()) k = mono.class_from_name(img, utf8Alloc(''), utf8Alloc('MatchManager+GameResult'));
      if (k.isNull()) {
        // Fallback: look at an instance from live manager
        const wrapper = getWrapperController();
        const mgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
        const grList = propGet(mgr, mono.object_get_class(mgr), 'GameResults');
        if (grList && !grList.isNull()) {
          const lk = mono.object_get_class(grList);
          const itf = mono.class_get_field_from_name(lk, utf8Alloc('_items'));
          const items = mono.field_get_value_object(rootDomain, itf, grList);
          if (!items.isNull()) {
            const arrKlass = mono.object_get_class(items);
            const elemKlass = mono.class_get_element_class(arrKlass);
            if (!elemKlass.isNull()) k = elemKlass;
          }
        }
      }
      if (!k || k.isNull()) return send({ type: 'dump_game_result_type', id: msg.id || null, data: { error: 'GameResult class not found' } });
      return send({ type: 'dump_game_result_type', id: msg.id || null, data: {
        typeName: classNameOf(k),
        isValueType: mono.class_is_valuetype(k) !== 0,
        fields: enumFields(k),
        properties: enumProperties(k),
      }});
    }
    if (msg.op === 'dump_match_manager') {
      ensureAttached();
      const wrapper = getWrapperController();
      const mgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
      if (!mgr) return send({ type: 'dump_match_manager', id: msg.id || null, data: { error: 'null' } });
      const klass = mono.object_get_class(mgr);
      return send({ type: 'dump_match_manager', id: msg.id || null, data: {
        typeName: classNameOf(klass),
        fields: enumFields(klass),
        properties: enumProperties(klass),
      }});
    }
    if (msg.op === 'dump_match_subobjects') {
      ensureAttached();
      const wrapper = getWrapperController();
      const mgr = fieldObj(wrapper, cache.wrapperKlass, '_matchManager');
      if (!mgr) return send({ type: 'dump_match_subobjects', id: msg.id || null, data: { error: 'null' } });
      const klass = mono.object_get_class(mgr);
      const out = {};
      for (const propName of (msg.names || ['LocalPlayerInfo','OpponentInfo','Event','GreConnection','Players','MessageHistory'])) {
        let obj = propGet(mgr, klass, propName);
        if (!obj) obj = fieldObj(mgr, klass, propName);
        out[propName] = obj && !obj.isNull() ? dumpType(obj) : null;
      }
      return send({ type: 'dump_match_subobjects', id: msg.id || null, data: out });
    }
    if (msg.op === 'dump_card_struct') {
      ensureAttached();
      // Find class via searching assemblies — simpler: get first card's array element class
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let target = null;
      iterateList(list, (d) => {
        if (target) return;
        const summary = propGet(d, mono.object_get_class(d), 'Summary');
        const nameObj = fieldObj(summary, mono.object_get_class(summary), 'Name');
        if (monoStringToJs(nameObj) === msg.name) target = d;
      });
      const contents = propGet(target, mono.object_get_class(target), 'Contents');
      const piles = fieldObj(contents, mono.object_get_class(contents), 'Piles');
      const dk = mono.object_get_class(piles);
      const entriesField = mono.class_get_field_from_name(dk, utf8Alloc('_entries'));
      const entriesArr = mono.field_get_value_object(rootDomain, entriesField, piles);
      const dictStride = mono.array_element_size(mono.object_get_class(entriesArr));
      const dictValueOffset = dictStride - Process.pointerSize;
      const firstEntry = entriesArr.add(32);
      const mainList = firstEntry.add(dictValueOffset).readPointer();
      const lk = mono.object_get_class(mainList);
      const itf = mono.class_get_field_from_name(lk, utf8Alloc('_items'));
      const items = mono.field_get_value_object(rootDomain, itf, mainList);
      const arrKlass = mono.object_get_class(items);
      const elementSize = mono.array_element_size(arrKlass);
      const elementClass = mono.class_get_element_class(arrKlass);
      const isValueType = mono.class_is_valuetype(elementClass) !== 0;
      // Enumerate fields of element class with offsets
      const fields = [];
      const iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(NULL);
      for (;;) {
        const f = mono.class_get_fields(elementClass, iter);
        if (f.isNull()) break;
        fields.push({
          name: cstr(mono.field_get_name(f)),
          offset: mono.field_get_offset(f),
          type: cstr(mono.type_get_name(mono.field_get_type(f))),
        });
      }
      return send({ type: 'dump_card_struct', id: msg.id || null, data: {
        elementClassName: classNameOf(elementClass),
        elementSize, isValueType, fields,
      }});
    }
    if (msg.op === 'dump_list_bytes') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let target = null;
      iterateList(list, (d) => {
        if (target) return;
        const summary = propGet(d, mono.object_get_class(d), 'Summary');
        const nameObj = fieldObj(summary, mono.object_get_class(summary), 'Name');
        if (monoStringToJs(nameObj) === msg.name) target = d;
      });
      const contents = propGet(target, mono.object_get_class(target), 'Contents');
      const piles = fieldObj(contents, mono.object_get_class(contents), 'Piles');
      const dk = mono.object_get_class(piles);
      const entriesField = mono.class_get_field_from_name(dk, utf8Alloc('_entries'));
      const entriesArr = mono.field_get_value_object(rootDomain, entriesField, piles);
      const stride = mono.array_element_size(mono.object_get_class(entriesArr));
      const valueOffset = stride - Process.pointerSize;
      // Find key 1 (MainDeck) entry
      const entry0 = entriesArr.add(32); // vector start assumption
      const key = entry0.add(8).readS32();
      const listPtr = entry0.add(valueOffset).readPointer();
      // Dump the list object's header: 16 bytes header + fields
      const bytes = [];
      for (let off = 0; off < 80; off += 8) {
        try { bytes.push({ off, u64: listPtr.add(off).readU64().toString() }); } catch (e) { bytes.push({ off, err: String(e) }); }
      }
      // Also _size and _items via field lookup
      const lk = mono.object_get_class(listPtr);
      const szf = mono.class_get_field_from_name(lk, utf8Alloc('_size'));
      const itf = mono.class_get_field_from_name(lk, utf8Alloc('_items'));
      const szOff = mono.field_get_offset ? null : null;  // helper not bound
      const b = Memory.alloc(4);
      mono.field_get_value(listPtr, szf, b);
      const sz = b.readS32();
      const items = mono.field_get_value_object(rootDomain, itf, listPtr);
      // Dump items array bytes
      const itemBytes = [];
      for (let off = 0; off < 128; off += 8) {
        try { itemBytes.push({ off, u64: items.add(off).readU64().toString() }); } catch (e) { itemBytes.push({ off, err: String(e) }); }
      }
      return send({ type: 'dump_list_bytes', id: msg.id || null, data: {
        entryKey: key,
        listPtr: listPtr.toString(),
        listBytes: bytes,
        listSize: sz,
        itemsType: classNameOf(mono.object_get_class(items)),
        itemsPtr: items.toString(),
        itemBytes,
      }});
    }
    if (msg.op === 'dump_deck_by_name') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let target = null;
      iterateList(list, (d) => {
        if (target) return;
        const summary = propGet(d, mono.object_get_class(d), 'Summary');
        if (!summary) return;
        const nameObj = fieldObj(summary, mono.object_get_class(summary), 'Name');
        const name = monoStringToJs(nameObj);
        if (name === msg.name) target = d;
      });
      if (!target) return send({ type: 'dump_deck_by_name', id: msg.id || null, data: { error: 'not found' } });
      const contents = propGet(target, mono.object_get_class(target), 'Contents');
      const piles = fieldObj(contents, mono.object_get_class(contents), 'Piles');
      const dk = mono.object_get_class(piles);
      let entriesField = mono.class_get_field_from_name(dk, utf8Alloc('_entries'));
      let countField = mono.class_get_field_from_name(dk, utf8Alloc('_count'));
      const buf = Memory.alloc(4);
      mono.field_get_value(piles, countField, buf);
      const count = buf.readS32();
      const entriesArr = mono.field_get_value_object(rootDomain, entriesField, piles);
      const stride = mono.array_element_size(mono.object_get_class(entriesArr));
      const valueOffset = stride - Process.pointerSize;
      const rawEntries = [];
      for (let i = 0; i < count; i++) {
        const entry = mono.array_addr_with_size(entriesArr, stride, i);
        rawEntries.push({
          i,
          hashCode: entry.readS32(),
          next: entry.add(4).readS32(),
          key: entry.add(8).readS32(),
          valuePtr: entry.add(valueOffset).readPointer().toString(),
        });
      }
      // Also return serialized deck via normal path
      return send({ type: 'dump_deck_by_name', id: msg.id || null, data: {
        meta: { count, stride, valueOffset },
        rawEntries,
        serialized: serializeDeck(target),
      }});
    }
    if (msg.op === 'dump_entry_bytes') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let first = null;
      iterateList(list, (d, i) => { if (i === 0) first = d; });
      const contents = propGet(first, mono.object_get_class(first), 'Contents');
      const piles = fieldObj(contents, mono.object_get_class(contents), 'Piles');
      const dk = mono.object_get_class(piles);
      let entriesField = mono.class_get_field_from_name(dk, utf8Alloc('_entries'));
      let countField = mono.class_get_field_from_name(dk, utf8Alloc('_count'));
      const buf = Memory.alloc(4);
      mono.field_get_value(piles, countField, buf);
      const count = buf.readS32();
      const entriesArr = mono.field_get_value_object(rootDomain, entriesField, piles);
      const arrKlass = mono.object_get_class(entriesArr);
      const stride = mono.array_element_size(arrKlass);
      const arrLen = mono.array_length(entriesArr).valueOf();
      const first8 = [];
      if (count > 0 && !entriesArr.isNull()) {
        const base = mono.array_addr_with_size(entriesArr, stride, 0);
        // Dump first 48 bytes as 6 u64 words
        for (let o = 0; o < 48; o += 8) {
          first8.push({ off: o, u64: base.add(o).readU64().toString() });
        }
      }
      return send({ type: 'dump_entry_bytes', id: msg.id || null, data: {
        count, stride, arrLen,
        pilesType: classNameOf(dk),
        words: first8,
      }});
    }
    if (msg.op === 'dump_piles_dict') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let first = null;
      iterateList(list, (d, i) => { if (i === 0) first = d; });
      const contents = propGet(first, mono.object_get_class(first), 'Contents');
      const piles = fieldObj(contents, mono.object_get_class(contents), 'Piles');
      return send({ type: 'dump_piles_dict', id: msg.id || null, data: dumpType(piles) });
    }
    if (msg.op === 'dump_deck_internals') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const list = methodInvoke(mono.object_get_class(decksMgr), 'GetAllCachedDecks', 0, decksMgr, null);
      let first = null;
      iterateList(list, (d, i) => { if (i === 0) first = d; });
      const fk = mono.object_get_class(first);
      const contents = propGet(first, fk, 'Contents');
      const ck = mono.object_get_class(contents);
      // Piles is a field (as per shape output)
      const piles = fieldObj(contents, ck, 'Piles');
      if (!piles) return send({ type: 'dump_deck_internals', id: msg.id || null, data: { error: 'Piles null' } });
      const pilesKlass = mono.object_get_class(piles);
      const out = {
        pilesTypeName: classNameOf(pilesKlass),
        pilesFields: enumFields(pilesKlass),
        firstCardType: null,
      };
      // Try to grab first card from first non-empty pile by walking entries array
      const entriesField = mono.class_get_field_from_name(pilesKlass, utf8Alloc('entries'));
      if (!entriesField.isNull()) {
        const entriesArr = mono.field_get_value_object(rootDomain, entriesField, piles);
        if (entriesArr && !entriesArr.isNull()) {
          const len = mono.array_length(entriesArr).toNumber();
          out.entriesLen = len;
          // Entry struct — we don't know its exact size, but value V (ref) is near end.
          // Instead, try the generic 'count' field.
        }
      }
      return send({ type: 'dump_deck_internals', id: msg.id || null, data: out });
    }
    if (msg.op === 'dump_deck_subtypes') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      const decksMgrKlass = mono.object_get_class(decksMgr);
      const list = methodInvoke(decksMgrKlass, 'GetAllCachedDecks', 0, decksMgr, null);
      let first = null;
      iterateList(list, (d, i) => { if (i === 0) first = d; });
      const fk = mono.object_get_class(first);
      const summary = propGet(first, fk, 'Summary');
      const contents = propGet(first, fk, 'Contents');
      return send({ type: 'dump_deck_subtypes', id: msg.id || null, data: {
        summary: summary ? dumpType(summary) : null,
        contents: contents ? dumpType(contents) : null,
      }});
    }
    if (msg.op === 'dump_decks_manager_shape') {
      ensureAttached();
      const wrapper = getWrapperController();
      const decksMgr = getManagerVia(wrapper, 'DecksManager');
      if (!decksMgr) return send({ type: 'dump_decks_manager_shape', id: msg.id || null, data: { error: 'null' } });
      const klass = mono.object_get_class(decksMgr);
      cache.decksManagerKlass = klass;
      // Also enumerate methods
      const methodsIter = Memory.alloc(Process.pointerSize);
      methodsIter.writePointer(NULL);
      const methods = [];
      for (;;) {
        const m = mono.class_get_methods(klass, methodsIter);
        if (m.isNull()) break;
        const n = cstr(mono.method_get_name(m));
        if (n) methods.push(n);
      }
      return send({ type: 'dump_decks_manager_shape', id: msg.id || null, data: {
        typeName: classNameOf(klass),
        fields: enumFields(klass),
        properties: enumProperties(klass),
        methods: methods,
      }});
    }
    send({ type: 'error', error: 'unknown op: ' + msg.op });
  } catch (e) {
    send({ type: 'error', error: String(e), stack: (e && e.stack) || null });
  }
}

function pump() {
  recv((msg) => { onMessage(msg); pump(); });
}

init();
pump();
