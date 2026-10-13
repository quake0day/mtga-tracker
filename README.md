# MTGA Tracker

Local Magic: The Gathering Arena deck tracker + match recorder. Reads live
game state from the running `MTGA.exe` via Frida + Mono reflection, serves a
dashboard over HTTP + WebSocket.

Reads only your own client state (same approach as every mainstream MTGA
tracker — Untapped.gg, 17Lands etc. — but via in-process reflection for
sub-second updates instead of log tailing).

## Features

- **Saved decks** — all 180+ decks in your collection, main + sideboard with
  resolved card names, mana cost, colors, rarity, set code
- **Live match** — in-game: opponent name/rank, format, double-digit life
  totals, hand size, mana pool, mulligan count
- **Zone view** — current hand, battlefield, graveyard, exile for you + opponent
  with tapped-state indicators
- **Card timeline** — real-time log of every card that enters a zone (your
  draws, opponent's plays), sub-second latency via Mono method hooks
- **Match history** — persistent SQLite log of every match: timestamp, format,
  opponent, rank, games won/lost, final result
- **Stats** — overall + last-7-day + per-format win rate
- **Owned cards** — 6000+ owned-card inventory with searchable filters
  (rarity / color / set)
- **Scryfall images** — hover any card for its illustration

## Architecture

```
MTGA.exe (Unity + Mono runtime)
  └─ frida_agent.js  (loaded in-process via Frida)
       - resolves mono-2.0-bdwgc.dll exports
       - walks WrapperController.Instance → Decks / Inventory / MatchManager
       - reads GreInterface._currentGameState (zones / cards / players)
       - hooks set_MatchState, GI_ParseFullGameStateMessage etc.
         to push events sub-second instead of 2s polling
  ↓  (Frida IPC)
backend/server.py  (Python / FastAPI)
  - drives Frida agent, enriches raw grpIds with card DB
  - persists match history to SQLite with win/loss identification
  - proxies Scryfall images (adds required User-Agent header, local cache)
  - fans snapshots + timeline events to WS clients
  ↓  (WebSocket + REST)
web/index.html  (vanilla JS, no bundler)
  - 3 tabs: Live / History / Inventory
  - diff-based rendering (deck list doesn't flicker on 1-second refreshes)
```

## Prerequisites

- Windows (MTGA is Windows-only, Mono runtime assumed to be at
  `MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll` next to `MTGA.exe`)
- Python 3.11+
- MTGA installed, launched, and signed in

## Setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python server.py
```

Then open <http://localhost:8765/>.

The server attaches to the already-running MTGA.exe on startup. If MTGA isn't
running when you start the server, launch MTGA and restart the server (Frida
can't swap targets mid-session).

## Key reverse-engineering findings

Found via static analysis + Frida reflection on
`MTGA_Data/Managed/*.dll` (Mono-managed, not IL2CPP):

- **`Core.dll`** (12 MB) holds the main game logic — not `Assembly-CSharp.dll`
  (which is only 300 KB of glue). Master singleton is global-namespace
  `WrapperController` with a static `get_Instance()`.
- **`SharedClientCore.dll`** holds `GreClient.Rules.GreInterface` which owns
  `_currentGameState` (an `MtgGameState`) with `Zones` / `AllCards` /
  `VisibleCards` / `Players` / phase / step / turn.
- **`Wizards.MDN.GreProtobuf.dll`** owns the GRE wire enums:
  `ZoneType` (14 values, 1=Library, 2=Hand, 3=Battlefield, 4=Stack, 5=Graveyard, 6=Exile, ...),
  `Phase`, `Step`, `MatchState`, `SuperFormat`, `GameVariant`.
- **Card database**: `MTGA_Data/Downloads/Raw/Raw_CardDatabase_*.mtga` is a
  **plain SQLite** file (`.mtga` extension is misleading) with a `Cards` table
  joined to `Localizations_enUS` for name resolution.

### Mono-on-Windows-x64 gotchas

Collected while debugging the Frida agent. If you're writing one yourself:

1. **`'ulong'` is 4 bytes on Windows (LLP64)**, but Mono's `uintptr_t` / array
   size parameters are 8 bytes. Use `'uint64'` in Frida bindings, not `'ulong'`.
2. **`MonoArray` header is 32 bytes** on x64. Empirically `bounds` precedes
   `max_length` (offsets 16 and 24) in Unity's bdwgc Mono, which differs from
   the Mono source ordering.
3. **`mono_field_get_offset` returns the BOXED offset** for value-type struct
   fields — subtract `sizeof(MonoObject)` (16 bytes) when reading inline
   structs out of arrays or struct-valued dictionary values.
4. **Mono's `Dictionary<K,V>` uses `_entries` and `_count`** (underscore
   prefix); newer .NET Core variants use `entries` / `count`. Try both.
5. **Reference-type arrays and value-type arrays look the same from `Frida`'s
   `array_addr_with_size`**. Use `mono_class_is_valuetype(element_class)` to
   tell them apart, otherwise `addr.readPointer()` on a struct address
   returns garbage interpreted as a pointer and crashes.

See `backend/frida_agent.js` for the working implementation.

## Legality

MTG Arena has no kernel anti-cheat. This project **only reads** process memory
(no writes, no injection beyond what Frida does to run the agent). Every
mainstream MTGA tracker — Untapped.gg, 17Lands, MTGATracker — does the same
thing, just via log-file tailing which this project chose not to do because
sub-second updates needed in-memory reflection. Reading your own client state
is covered by Wizards' tracker ToS carve-out.

## Files

```
backend/
  frida_agent.js      Mono reflection agent (loaded into MTGA.exe)
  server.py           FastAPI driver + WebSocket hub
  cards.py            SQLite card DB loader + Scryfall URL helper
  history.py          Match history store + stats aggregator
  requirements.txt    frida / fastapi / uvicorn
web/
  index.html          Single-page dashboard
run.ps1               bootstrap: creates venv, installs deps, launches server
```

## License

Personal project. No warranty, no support, no implied endorsement by Wizards
of the Coast.
