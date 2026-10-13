"""MTGA local card database loader.

Reads the Raw_CardDatabase .mtga SQLite shipped with the game, builds an
in-memory dict keyed by GrpId, resolves names via Localizations_enUS, decodes
the color/type/rarity enums. Used by server.py to enrich snapshots so the UI
can show card names instead of raw grpIds.
"""

from __future__ import annotations

import glob
import logging
import pathlib
import sqlite3
from dataclasses import dataclass, asdict
from typing import Any

log = logging.getLogger(__name__)

MTGA_DOWNLOADS = pathlib.Path("E:/SteamLibrary/steamapps/common/MTGA/MTGA_Data/Downloads/Raw")

# Rarity: verified empirically against known cards. MTGA uses 6 values with
# Basic lands as their own tier below Common.
#   0 = Token / unprintable  (1308 cards in DB)
#   1 = Basic (basic lands)   (1316)
#   2 = Common                (6955)
#   3 = Uncommon              (7281)
#   4 = Rare                  (6928)
#   5 = Mythic                (3283)
# Spot checks: Plains=1, Narset Parter of Veils=3, Hallowed Fountain=4,
# Ugin the Spirit Dragon=5, Jace the Mind Sculptor=5.
RARITY_NAMES = {0: "Token", 1: "Basic", 2: "Common", 3: "Uncommon", 4: "Rare", 5: "Mythic"}

# Color enum (verified): 1=White 2=Blue 3=Black 4=Red 5=Green
COLOR_SYMBOL = {1: "W", 2: "U", 3: "B", 4: "R", 5: "G"}

# CardType enum (verified)
CARD_TYPE_NAMES = {
    1: "Artifact", 2: "Creature", 3: "Enchantment", 4: "Instant", 5: "Land",
    6: "Phenomenon", 7: "Plane", 8: "Planeswalker", 9: "Scheme", 10: "Sorcery",
    11: "Kindred", 12: "Vanguard", 13: "Dungeon", 14: "Battle", 15: "Conspiracy",
}


def _parse_csv_ints(s: str | None) -> list[int]:
    if not s:
        return []
    out = []
    for tok in s.split(","):
        tok = tok.strip()
        if tok.isdigit():
            out.append(int(tok))
    return out


def _format_mana(old_school: str | None) -> str:
    """Convert MTGA's 'o1oUoU' format to a plain string like '1UU'."""
    if not old_school:
        return ""
    # 'o' is a leading separator before each symbol; strip 'o' and keep the rest.
    parts = [p for p in old_school.split("o") if p]
    return "".join(parts)


# MTGA ExpansionCode → Scryfall set code. Most match 1:1 lowercased, but some
# diverge (e.g., promo/arena-only sets). Known mappings; unknowns pass through.
MTGA_TO_SCRYFALL_SET: dict[str, str] = {
    "DAR": "dom",      # Dominaria
    "ANA": "ana",
    "ANB": "anb",
    "ARENA": "pana",
    # Most sets: just lowercase
}


def _scryfall_image_url(set_code: str, collector: str, size: str = "small") -> str | None:
    """Historical: Scryfall used to serve direct ?format=image, but now requires
    a User-Agent header which browsers cannot set for <img>. We now proxy via
    /api/img/{grpId} server-side. This helper is kept only for callers that
    want the raw Scryfall URL for debugging."""
    if not set_code or not collector:
        return None
    s = MTGA_TO_SCRYFALL_SET.get(set_code, set_code).lower()
    return f"https://api.scryfall.com/cards/{s}/{collector}?format=image&version={size}"


def scryfall_json_url(set_code: str, collector: str) -> str | None:
    if not set_code or not collector:
        return None
    s = MTGA_TO_SCRYFALL_SET.get(set_code, set_code).lower()
    return f"https://api.scryfall.com/cards/{s}/{collector}"


@dataclass
class CardInfo:
    GrpId: int
    Name: str
    Rarity: str
    Colors: str          # e.g. "WU"
    Types: list[str]     # e.g. ["Planeswalker"]
    ManaCost: str        # e.g. "1WU"
    SetCode: str
    Power: str
    Toughness: str
    CollectorNumber: str
    IsToken: bool
    ImageUrl: str | None  # Scryfall redirect URL for small image


class CardDatabase:
    def __init__(self, cards: dict[int, CardInfo]) -> None:
        self._cards = cards

    def get(self, grp_id: int) -> CardInfo | None:
        return self._cards.get(grp_id)

    def enrich(self, grp_id: int) -> dict[str, Any] | None:
        info = self._cards.get(grp_id)
        return asdict(info) if info else None

    def __len__(self) -> int:
        return len(self._cards)

    @classmethod
    def load(cls, downloads_dir: pathlib.Path | None = None) -> "CardDatabase":
        root = downloads_dir or MTGA_DOWNLOADS
        matches = glob.glob(str(root / "Raw_CardDatabase_*.mtga"))
        if not matches:
            raise FileNotFoundError(f"No Raw_CardDatabase_*.mtga in {root}")
        db_path = max(matches, key=lambda p: pathlib.Path(p).stat().st_mtime)
        log.info("Loading card database: %s", db_path)
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            cards: dict[int, CardInfo] = {}
            cur = conn.execute(
                """
                SELECT c.GrpId, c.TitleId, c.Rarity, c.Colors, c.Types,
                       c.OldSchoolManaText, c.ExpansionCode, c.Power, c.Toughness,
                       c.CollectorNumber, c.IsToken, c.IsPrimaryCard,
                       loc.Loc AS Name
                FROM Cards c
                LEFT JOIN Localizations_enUS loc ON c.TitleId = loc.LocId
                """
            )
            for row in cur:
                grp = int(row["GrpId"])
                color_ints = _parse_csv_ints(row["Colors"])
                type_ints = _parse_csv_ints(row["Types"])
                set_code = row["ExpansionCode"] or ""
                collector = row["CollectorNumber"] or ""
                cards[grp] = CardInfo(
                    GrpId=grp,
                    Name=row["Name"] or f"<grpId {grp}>",
                    Rarity=RARITY_NAMES.get(int(row["Rarity"] or 0), ""),
                    Colors="".join(COLOR_SYMBOL.get(c, "?") for c in color_ints),
                    Types=[CARD_TYPE_NAMES.get(t, f"Type{t}") for t in type_ints],
                    ManaCost=_format_mana(row["OldSchoolManaText"]),
                    SetCode=set_code,
                    Power=row["Power"] or "",
                    Toughness=row["Toughness"] or "",
                    CollectorNumber=collector,
                    IsToken=bool(row["IsToken"]),
                    # Browser hits our proxy; we fetch Scryfall server-side with
                    # the required User-Agent header and cache the image.
                    ImageUrl=f"/api/img/{grp}" if set_code and collector else None,
                )
        finally:
            conn.close()
        log.info("Loaded %d cards", len(cards))
        return cls(cards)
