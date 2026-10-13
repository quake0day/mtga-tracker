"""MTGA Deck Tracker backend.

Drives a Frida agent inside MTGA.exe, exposes HTTP + WebSocket to the Web UI.

Dev run:
    pip install -r requirements.txt
    python server.py

Then open http://localhost:8765/
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import pathlib
import threading
import time
from typing import Any

import json as _json
import urllib.request
import urllib.error

import frida
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from cards import CardDatabase, scryfall_json_url
from history import MatchHistoryStore

HERE = pathlib.Path(__file__).resolve().parent
AGENT_PATH = HERE / "frida_agent.js"
WEB_ROOT = HERE.parent / "web"
HISTORY_PATH = HERE.parent / "data" / "matches.sqlite"
IMG_CACHE_DIR = HERE.parent / "data" / "card_images"
SCRYFALL_UA = "MTGATracker/1.0 (local personal tool; contact: user)"

TARGET_PROCESS = "MTGA.exe"
POLL_INTERVAL_SEC = 2.0  # background snapshot cadence

log = logging.getLogger("mtga-tracker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


class FridaBridge:
    """Owns the Frida session + agent script. Thread-safe snapshot RPC."""

    def __init__(self) -> None:
        self._session: frida.core.Session | None = None
        self._script: frida.core.Script | None = None
        self._ready = threading.Event()
        self._pending: dict[int, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._next_id = 1
        self.last_snapshot: dict[str, Any] | None = None
        self.last_error: str | None = None
        self.attached_pid: int | None = None
        # Event bridge: hook callbacks push events here; the poller task
        # consumes them to trigger immediate snapshots.
        self.event_queue: asyncio.Queue | None = None
        self.event_loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    def attach(self) -> None:
        log.info("Attaching to %s", TARGET_PROCESS)
        # Resolve PID separately — Frida's Session doesn't expose it as an attribute.
        try:
            proc = frida.get_local_device().get_process(TARGET_PROCESS)
            self.attached_pid = proc.pid
        except Exception as e:
            log.warning("Could not resolve PID for %s: %s", TARGET_PROCESS, e)
            self.attached_pid = None
        self._session = frida.attach(self.attached_pid or TARGET_PROCESS)
        src = AGENT_PATH.read_text(encoding="utf-8")
        self._script = self._session.create_script(src)
        self._script.on("message", self._on_message)
        self._script.load()
        # Wait for ready signal (agent sends {type:"ready", ...} after bindMono)
        if not self._ready.wait(timeout=10):
            raise RuntimeError("Frida agent did not report ready within 10s")
        log.info("Agent ready")

    def detach(self) -> None:
        with contextlib.suppress(Exception):
            if self._script:
                self._script.unload()
        with contextlib.suppress(Exception):
            if self._session:
                self._session.detach()

    # ------------------------------------------------------------------
    def _on_message(self, message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "error":
            self.last_error = message.get("description") or message.get("stack") or str(message)
            log.error("Agent error: %s", self.last_error)
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("type")
        if kind == "ready":
            self._ready.set()
            return
        if kind == "snapshot":
            self.last_snapshot = payload.get("data")
            self.last_error = None
            # Resolve any pending future with the matching id
            rpc_id = payload.get("id")
            if rpc_id is not None:
                with self._pending_lock:
                    fut = self._pending.pop(rpc_id, None)
                if fut:
                    fut["result"] = self.last_snapshot
                    fut["event"].set()
            return
        # Generic typed-response → resolve any pending RPC with matching id.
        rpc_id = payload.get("id") if isinstance(payload, dict) else None
        if rpc_id is not None and kind not in ("event",):
            with self._pending_lock:
                fut = self._pending.pop(rpc_id, None)
            if fut:
                fut["result"] = payload.get("data")
                fut["event"].set()
                return
        if kind == "error":
            self.last_error = payload.get("error")
            log.error("Agent reported error: %s", self.last_error)
            # Fail any pending RPCs
            with self._pending_lock:
                for fut in self._pending.values():
                    fut["error"] = self.last_error
                    fut["event"].set()
                self._pending.clear()
            return
        if kind == "pong":
            return
        if kind == "event":
            # Agent hook fired. Hand to the asyncio loop so poller can react.
            if self.event_queue is not None and self.event_loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self.event_queue.put(payload), self.event_loop
                )
            log.info("Agent event: %s=%s", payload.get("kind"), payload.get("payload"))
            return
        log.debug("Unhandled agent message: %s", payload)

    # ------------------------------------------------------------------
    def _rpc(self, op: str, timeout: float = 5.0, **extra) -> dict[str, Any]:
        """Blocking RPC helper for ops that return a typed response."""
        if not self._script:
            raise RuntimeError("Not attached")
        rpc_id = self._next_id
        self._next_id += 1
        ev = threading.Event()
        slot: dict[str, Any] = {"event": ev, "result": None, "error": None}
        with self._pending_lock:
            self._pending[rpc_id] = slot
        self._script.post({"op": op, "id": rpc_id, **extra})
        ev.wait(timeout)
        return slot.get("result") or {}

    def install_hooks(self) -> dict[str, Any]:
        return self._rpc("install_hooks")

    def install_gre_hooks(self) -> dict[str, Any]:
        return self._rpc("install_gre_hooks")

    def snapshot(self, timeout: float = 5.0) -> dict[str, Any]:
        if not self._script:
            raise RuntimeError("Not attached")
        rpc_id = self._next_id
        self._next_id += 1
        ev = threading.Event()
        slot: dict[str, Any] = {"event": ev, "result": None, "error": None}
        with self._pending_lock:
            self._pending[rpc_id] = slot
        self._script.post({"op": "snapshot", "id": rpc_id})
        if not ev.wait(timeout):
            with self._pending_lock:
                self._pending.pop(rpc_id, None)
            raise TimeoutError("Agent snapshot timed out")
        if slot["error"]:
            raise RuntimeError(slot["error"])
        return slot["result"]


bridge = FridaBridge()
card_db: CardDatabase | None = None
history_store: MatchHistoryStore | None = None


class CardTimeline:
    """Tracks zone transitions of card instances across consecutive game-state
    snapshots. Emits one event when a card first becomes visible in a given
    zone (play, draw-into-hand, graveyard-from-play, etc.). Keyed by MatchID
    + GameNumber so a new game resets the state."""

    def __init__(self) -> None:
        self._prev: dict[tuple[str | None, int], dict[int, int]] = {}  # (match, game) -> {instanceId: zoneType}
        self._events: list[dict[str, Any]] = []

    def ingest(self, snap: dict[str, Any]) -> list[dict[str, Any]]:
        match = snap.get("match") or {}
        gs = match.get("GameState") or {}
        cards = gs.get("Cards") or []
        if not match.get("MatchID") or not cards:
            return []
        key = (match["MatchID"], int(match.get("CurrentGameNumber") or 0))
        prev = self._prev.get(key, {})
        current = {}
        my_seat = gs.get("MySeatId")
        new_events: list[dict[str, Any]] = []
        for c in cards:
            iid = c.get("InstanceId")
            z = c.get("ZoneType")
            if iid is None or z is None:
                continue
            current[iid] = z
            old = prev.get(iid)
            if old != z:
                # Zone transition: emit event
                ev = {
                    "ts": time.time(),
                    "turn": gs.get("GameWideTurn"),
                    "phase": gs.get("CurrentPhaseName"),
                    "step": gs.get("CurrentStepName"),
                    "match_id": match["MatchID"],
                    "game_number": key[1],
                    "instance_id": iid,
                    "grp_id": c.get("GrpId"),
                    "name": c.get("Name"),
                    "image_url": c.get("ImageUrl"),
                    "from_zone": old,
                    "to_zone": z,
                    "to_zone_name": c.get("ZoneTypeName"),
                    "controller": c.get("ControllerSeatId"),
                    "is_me": c.get("ControllerSeatId") == my_seat,
                }
                new_events.append(ev)
        self._prev[key] = current
        if new_events:
            self._events.extend(new_events)
            # Cap in-memory ring
            if len(self._events) > 2000:
                self._events = self._events[-1500:]
        return new_events

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._events[-limit:][::-1]


timeline = CardTimeline()


def _aggregate_grp_list(grps: list[int]) -> list[dict[str, Any]]:
    """Turn [1,1,2,3,3,3] into [{Id:1, Quantity:2}, {Id:2, Quantity:1}, {Id:3, Quantity:3}]
    and enrich each with card metadata."""
    counts: dict[int, int] = {}
    for g in grps:
        if isinstance(g, int):
            counts[g] = counts.get(g, 0) + 1
    out = []
    for grp, qty in counts.items():
        info = card_db.enrich(grp) if card_db else None
        entry = {"Id": grp, "Quantity": qty}
        if info:
            entry.update({k: v for k, v in info.items() if k not in entry})
        out.append(entry)
    return out


def enrich_snapshot(snap: dict[str, Any]) -> dict[str, Any]:
    """Resolve grpIds in every pile, in the match, and in the inventory."""
    if not card_db or not isinstance(snap, dict):
        return snap
    decks = snap.get("decks") or {}
    for deck in decks.get("decks") or []:
        piles = deck.get("Piles") or {}
        for pile_name, cards in list(piles.items()):
            if not isinstance(cards, list):
                continue
            for card in cards:
                grp = card.get("Id")
                if isinstance(grp, int):
                    info = card_db.enrich(grp)
                    if info:
                        card.update({k: v for k, v in info.items() if k not in card})
    # Enrich inventory
    inv = snap.get("inventory") or {}
    inv_cards = inv.get("cards")
    if isinstance(inv_cards, list):
        for card in inv_cards:
            grp = card.get("Id")
            if isinstance(grp, int):
                info = card_db.enrich(grp)
                if info:
                    card.update({k: v for k, v in info.items() if k not in card})
    # Enrich current match deck lists (local + opponent)
    match = snap.get("match") or {}
    for player_key in ("LocalPlayer", "Opponent"):
        pi = match.get(player_key)
        if not isinstance(pi, dict):
            continue
        for list_key in ("DeckCards", "SideboardCards"):
            grps = pi.get(list_key)
            if isinstance(grps, list) and grps:
                pi[list_key + "Aggregated"] = _aggregate_grp_list(grps)
    # Enrich live game state cards: resolve GrpId → name/cost/colors/image
    gs = match.get("GameState") or {}
    cards = gs.get("Cards") or []
    if isinstance(cards, list):
        for card in cards:
            grp = card.get("GrpId")
            if isinstance(grp, int):
                info = card_db.enrich(grp)
                if info:
                    card.update({k: v for k, v in info.items() if k not in card})
    return snap


# ---------------------------------------------------------------------------
# Background poller + WebSocket fanout
# ---------------------------------------------------------------------------

class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.latest: dict[str, Any] | None = None

    async def register(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)
        if self.latest:
            with contextlib.suppress(Exception):
                await ws.send_json({"type": "snapshot", "data": self.latest})

    def unregister(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, msg: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


hub = Hub()


def _slim_for_broadcast(snap: dict[str, Any]) -> dict[str, Any]:
    """Strip the big inventory list from WS broadcasts; keep just the summary.
    The full list is still available via /api/inventory on demand."""
    inv = snap.get("inventory")
    if isinstance(inv, dict) and isinstance(inv.get("cards"), list):
        snap = dict(snap)
        snap["inventory"] = {
            "cardsTypeName": inv.get("cardsTypeName"),
            "cardCount": inv.get("cardCount"),
            "enumeratedCount": inv.get("enumeratedCount"),
        }
    return snap


async def poller() -> None:
    """Event-driven snapshot loop. Waits up to POLL_INTERVAL_SEC on the event
    queue; if an agent hook fires, snapshot immediately. Otherwise refresh on
    the fallback cadence."""
    loop = asyncio.get_running_loop()
    assert bridge.event_queue is not None
    while True:
        trigger_reason = None
        try:
            evt = await asyncio.wait_for(bridge.event_queue.get(), timeout=POLL_INTERVAL_SEC)
            trigger_reason = evt.get("kind")
        except asyncio.TimeoutError:
            trigger_reason = "poll"
        try:
            snap = await loop.run_in_executor(None, bridge.snapshot, 5.0)
            snap = enrich_snapshot(snap)
            snap["_trigger"] = trigger_reason
            hub.latest = snap
            await hub.broadcast({"type": "snapshot", "data": _slim_for_broadcast(snap)})
            new_tl_events = timeline.ingest(snap)
            if new_tl_events:
                await hub.broadcast({"type": "timeline", "events": new_tl_events})
            # Persist on event-driven triggers only (not every poll fallback)
            # and only when there's a real MatchID so we don't record idle state.
            if (
                history_store
                and trigger_reason in {"MatchState", "MatchID", "GameNumber", "GreIncoming", "GreGameStateParsed"}
                and (snap.get("match") or {}).get("MatchID")
            ):
                try:
                    history_store.record(snap)
                except Exception as e:
                    log.warning("History record failed: %s", e)
        except Exception as e:
            log.warning("Snapshot failed: %s", e)
            await hub.broadcast({"type": "error", "error": str(e)})


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="MTGA Tracker")


@app.on_event("startup")
async def _startup() -> None:
    global card_db, history_store
    try:
        card_db = CardDatabase.load()
    except Exception as e:
        log.warning("Card database unavailable: %s", e)
    try:
        history_store = MatchHistoryStore(HISTORY_PATH).open()
    except Exception as e:
        log.warning("History store disabled: %s", e)
    try:
        bridge.attach()
    except Exception as e:
        log.error("Attach failed: %s", e)
        # Server still starts so UI can show the error.
        bridge.last_error = str(e)
        return
    # Wire up the async event bridge, then install Match hooks.
    bridge.event_queue = asyncio.Queue()
    bridge.event_loop = asyncio.get_running_loop()
    try:
        hooks = await asyncio.get_running_loop().run_in_executor(None, bridge.install_hooks)
        log.info("Match hooks installed: %s", hooks)
    except Exception as e:
        log.warning("Match hook install failed: %s", e)
    try:
        gre = await asyncio.get_running_loop().run_in_executor(None, bridge.install_gre_hooks)
        installed_gre = {k: v for k, v in gre.items() if isinstance(v, dict) and v.get("installed")}
        log.info("GRE hooks installed (%d): %s", len(installed_gre), list(installed_gre.keys()))
        for k, v in gre.items():
            if isinstance(v, dict) and v.get("error") and not k.endswith("Interface") and k != "MessageHistory":
                log.info("  GRE hook %s failed: %s", k, v["error"])
        # Also log any class discovery info so we can expand on misses later.
        for key in ("MessageHistory", "GreInterface"):
            info = gre.get(key)
            if isinstance(info, dict):
                if "error" in info:
                    log.info("  %s: %s", key, info["error"])
                else:
                    methods_preview = info.get("methods", [])[:12]
                    log.info("  %s @ %s, methods: %s", key, info.get("image"), methods_preview)
    except Exception as e:
        log.warning("GRE hook install failed: %s", e)
    asyncio.create_task(poller())


@app.on_event("shutdown")
async def _shutdown() -> None:
    bridge.detach()


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html")


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({
        "attached": bridge._session is not None,
        "pid": bridge.attached_pid,
        "last_error": bridge.last_error,
        "has_snapshot": bridge.last_snapshot is not None,
    })


def _fetch_scryfall_image(grp: int) -> bytes | None:
    """Hit Scryfall JSON API with a UA, extract small image URL, fetch & return."""
    if not card_db:
        return None
    info = card_db.get(grp)
    if not info:
        return None
    url = scryfall_json_url(info.SetCode, info.CollectorNumber)
    if not url:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": SCRYFALL_UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        img_url = (data.get("image_uris") or {}).get("small") or (data.get("image_uris") or {}).get("normal")
        if not img_url:
            # Double-faced cards: use the first face
            faces = data.get("card_faces") or []
            if faces:
                img_url = (faces[0].get("image_uris") or {}).get("small")
        if not img_url:
            return None
        req2 = urllib.request.Request(img_url, headers={"User-Agent": SCRYFALL_UA})
        with urllib.request.urlopen(req2, timeout=10) as resp:
            return resp.read()
    except Exception as e:
        log.warning("Scryfall fetch failed for grp %d (%s/%s): %s",
                    grp, info.SetCode, info.CollectorNumber, e)
        return None


@app.get("/api/img/{grp}")
async def img_proxy(grp: int) -> Response:
    IMG_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cached = IMG_CACHE_DIR / f"{grp}.jpg"
    if cached.exists() and cached.stat().st_size > 0:
        return Response(content=cached.read_bytes(), media_type="image/jpeg",
                        headers={"Cache-Control": "public, max-age=604800"})
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _fetch_scryfall_image, grp)
    if not data:
        return Response(status_code=404)
    cached.write_bytes(data)
    return Response(content=data, media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=604800"})


@app.get("/api/inventory")
async def inventory() -> JSONResponse:
    """Return the full enriched owned-cards list. Separated from the WS feed
    because it's a few hundred KB and only changes after opening packs."""
    if hub.latest and isinstance(hub.latest.get("inventory"), dict):
        inv = hub.latest["inventory"]
        if isinstance(inv.get("cards"), list) and inv["cards"]:
            return JSONResponse(inv)
    # Fallback: take a fresh snapshot
    try:
        snap = await asyncio.get_running_loop().run_in_executor(None, bridge.snapshot, 5.0)
        snap = enrich_snapshot(snap)
        return JSONResponse(snap.get("inventory") or {})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/timeline")
async def api_timeline(limit: int = 200) -> JSONResponse:
    return JSONResponse({"events": timeline.recent(limit)})


@app.get("/api/history")
async def history(limit: int = 50) -> JSONResponse:
    if not history_store:
        return JSONResponse({"matches": [], "note": "history store unavailable"})
    return JSONResponse({"matches": history_store.recent(limit)})


@app.get("/api/stats")
async def stats() -> JSONResponse:
    if not history_store:
        return JSONResponse({"error": "history store unavailable"}, status_code=500)
    return JSONResponse(history_store.stats())


@app.get("/api/snapshot")
async def snapshot() -> JSONResponse:
    try:
        snap = await asyncio.get_running_loop().run_in_executor(None, bridge.snapshot, 5.0)
        snap = enrich_snapshot(snap)
        return JSONResponse(snap)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await hub.register(ws)
    try:
        while True:
            # keep connection alive; discard anything client sends for now
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.unregister(ws)


# Serve static web assets
if WEB_ROOT.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_ROOT)), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
