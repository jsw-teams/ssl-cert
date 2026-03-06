from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = {"providers": {}}

    def load(self) -> None:
        if not self.path.exists():
            self.data = {"providers": {}}
            return
        with self.path.open("r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.data.setdefault("providers", {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2, sort_keys=True)

    def get_provider(self, name: str) -> dict[str, Any]:
        return dict(self.data.get("providers", {}).get(name, {}))

    def set_provider(self, name: str, payload: dict[str, Any]) -> None:
        self.data.setdefault("providers", {})[name] = {
            **payload,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
