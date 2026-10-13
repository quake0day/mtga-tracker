"""Local match-history SQLite store.

Writes one row per MatchCompleted event, capturing:
  - timestamp, match id, format, variant, game number
  - local player (name, rank, deck grpIds)
  - opponent (name, rank, revealed deck grpIds)
  - raw match-manager snapshot (JSON blob for debugging)

API side:
  store = MatchHistoryStore(path).open()
  store.record(snapshot)    # called from the MatchState hook handler
  store.recent(50)          # most recent N matches
"""

from __future__ import annotations

import json
import logging
import pathlib
import sqlite3
import time
from typing import Any

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at REAL NOT NULL,          -- epoch seconds (first seen)
    completed_at REAL,                  -- epoch seconds (match_result observed)
    match_id TEXT,
    format TEXT,
    variant TEXT,
    game_number INTEGER,                -- max game number observed
    match_state TEXT,
    local_name TEXT,
    local_rank TEXT,
    local_deck_json TEXT,               -- JSON array of grpId
    opponent_name TEXT,
    opponent_rank TEXT,
    opponent_deck_json TEXT,
    is_practice INTEGER,
    is_private INTEGER,
    -- Result columns (populated when GameResults list is non-empty)
    local_games_won INTEGER DEFAULT 0,
    opponent_games_won INTEGER DEFAULT 0,
    winner TEXT,                        -- 'local' / 'opponent' / 'draw' / null if ongoing
    results_json TEXT,                  -- full GameResults list for audit
    raw_json TEXT                       -- full match object for debugging
);
CREATE INDEX IF NOT EXISTS idx_matches_recorded_at ON matches(recorded_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_matches_match_id ON matches(match_id) WHERE match_id IS NOT NULL;
"""


def _upgrade_schema(conn: sqlite3.Connection) -> None:
    """Add new columns on existing DBs without dropping data."""
    existing = {r[1] for r in conn.execute("PRAGMA table_info(matches)")}
    adds = [
        ("completed_at", "REAL"),
        ("local_games_won", "INTEGER DEFAULT 0"),
        ("opponent_games_won", "INTEGER DEFAULT 0"),
        ("winner", "TEXT"),
        ("results_json", "TEXT"),
    ]
    for col, decl in adds:
        if col not in existing:
            conn.execute(f"ALTER TABLE matches ADD COLUMN {col} {decl}")
    conn.commit()


class MatchHistoryStore:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> "MatchHistoryStore":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        _upgrade_schema(self._conn)
        log.info("Match history store: %s", self.path)
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @staticmethod
    def _player_rank(pi: dict[str, Any] | None) -> str:
        if not pi:
            return ""
        cls = pi.get("RankingClassName") or ""
        tier = pi.get("RankingTier") or ""
        myth = pi.get("MythicPercentile")
        if cls == "Mythic" and myth:
            return f"Mythic top {myth:.2f}%"
        return f"{cls} {tier}".strip()

    @staticmethod
    def _tally_results(results: list[dict[str, Any]], local_seat: int | None) -> dict[str, Any]:
        """Scan GameResults list; count game wins per side and determine match winner."""
        if not results or local_seat is None:
            return {"local_games_won": 0, "opponent_games_won": 0, "winner": None, "match_scope_hit": False}
        local_games = 0
        opp_games = 0
        match_winner_id: int | None = None
        match_scope_hit = False
        for r in results:
            if not isinstance(r, dict):
                continue
            wid = r.get("WinnerId")
            scope = r.get("Scope")
            scope_name = (r.get("ScopeName") or "").lower()
            is_game = scope == 1 or scope_name == "game"
            is_match = scope == 2 or scope_name == "match"
            if is_game:
                if wid == local_seat:
                    local_games += 1
                elif wid and wid != local_seat:
                    opp_games += 1
            if is_match and wid:
                match_winner_id = wid
                match_scope_hit = True
        winner: str | None = None
        if match_winner_id is not None:
            winner = "local" if match_winner_id == local_seat else "opponent"
        elif local_games or opp_games:
            # Partial — don't claim a winner until Match-scope row arrives.
            winner = None
        return {
            "local_games_won": local_games,
            "opponent_games_won": opp_games,
            "winner": winner,
            "match_scope_hit": match_scope_hit,
        }

    def record(self, snapshot: dict[str, Any]) -> int | None:
        """Insert or update a match row. One row per unique match_id — rows
        get UPDATEd with newer game numbers and final results as the match
        progresses."""
        if not self._conn:
            return None
        match = snapshot.get("match") or {}
        if not match.get("active"):
            return None
        match_id = match.get("MatchID")
        if not match_id:
            return None  # don't record idle-state placeholder rows
        game_number = match.get("CurrentGameNumber") or 0
        now = time.time()
        local = match.get("LocalPlayer") or {}
        opp = match.get("Opponent") or {}
        results = match.get("GameResults") or []
        tally = self._tally_results(results, local.get("SeatId"))
        existing = self._conn.execute(
            "SELECT id, game_number, winner FROM matches WHERE match_id=?",
            (match_id,),
        ).fetchone()
        results_json = json.dumps(results)
        if existing:
            # UPDATE: bump game_number if higher, set winner once decided
            new_game_number = max(existing["game_number"] or 0, game_number)
            new_winner = tally["winner"] or existing["winner"]
            completed_at = now if tally["match_scope_hit"] else None
            self._conn.execute(
                """UPDATE matches SET
                    match_state=?, game_number=?,
                    local_games_won=?, opponent_games_won=?,
                    winner=COALESCE(?, winner),
                    completed_at=COALESCE(completed_at, ?),
                    results_json=?, raw_json=?
                   WHERE id=?""",
                (
                    match.get("MatchStateName"),
                    new_game_number,
                    tally["local_games_won"],
                    tally["opponent_games_won"],
                    new_winner,
                    completed_at,
                    results_json,
                    json.dumps(match, default=str),
                    existing["id"],
                ),
            )
            self._conn.commit()
            if tally["match_scope_hit"] and not existing["winner"]:
                log.info("Match %s finalized: winner=%s (%d-%d)",
                         match_id, new_winner, tally["local_games_won"], tally["opponent_games_won"])
            return existing["id"]
        # INSERT new row
        completed_at = now if tally["match_scope_hit"] else None
        cur = self._conn.execute(
            """INSERT INTO matches (
                recorded_at, completed_at, match_id, format, variant, game_number, match_state,
                local_name, local_rank, local_deck_json,
                opponent_name, opponent_rank, opponent_deck_json,
                is_practice, is_private,
                local_games_won, opponent_games_won, winner, results_json, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                now, completed_at, match_id,
                match.get("FormatName"), match.get("VariantName"),
                game_number, match.get("MatchStateName"),
                local.get("ScreenName"), self._player_rank(local),
                json.dumps(local.get("DeckCards") or []),
                opp.get("ScreenName"), self._player_rank(opp),
                json.dumps(opp.get("DeckCards") or []),
                1 if match.get("IsPracticeGame") else 0,
                1 if match.get("IsPrivateGame") else 0,
                tally["local_games_won"], tally["opponent_games_won"], tally["winner"],
                results_json, json.dumps(match, default=str),
            ),
        )
        self._conn.commit()
        log.info("New match row: %s game %s opp=%s", match_id, game_number, opp.get("ScreenName"))
        return cur.lastrowid

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            """SELECT id, recorded_at, completed_at, match_id, format, variant, game_number,
                      match_state, local_name, local_rank, opponent_name, opponent_rank,
                      is_practice, is_private,
                      local_games_won, opponent_games_won, winner
               FROM matches ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        """Aggregated win/loss stats: overall, by format, by local deck."""
        if not self._conn:
            return {}
        base = """
          SELECT
            COUNT(*) AS matches,
            SUM(CASE WHEN winner='local' THEN 1 ELSE 0 END) AS wins,
            SUM(CASE WHEN winner='opponent' THEN 1 ELSE 0 END) AS losses,
            SUM(CASE WHEN winner IS NULL THEN 1 ELSE 0 END) AS ongoing,
            SUM(local_games_won) AS games_won,
            SUM(opponent_games_won) AS games_lost
        """
        overall = dict(self._conn.execute(f"{base} FROM matches WHERE match_id IS NOT NULL").fetchone())
        by_format = [
            dict(r) for r in self._conn.execute(
                f"{base}, format FROM matches WHERE format IS NOT NULL GROUP BY format ORDER BY matches DESC"
            )
        ]
        # 最近 7 天
        week_ago = time.time() - 7 * 86400
        last7 = dict(self._conn.execute(
            f"{base} FROM matches WHERE recorded_at >= ?", (week_ago,)
        ).fetchone())
        return {"overall": overall, "last_7d": last7, "by_format": by_format}
