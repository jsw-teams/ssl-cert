from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ProviderResult:
    provider: str
    changed: bool
    action: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunReport:
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    certificate: dict[str, Any] = field(default_factory=dict)
    providers: list[dict[str, Any]] = field(default_factory=list)

    def add(self, result: ProviderResult) -> None:
        self.providers.append(
            {
                "provider": result.provider,
                "changed": result.changed,
                "action": result.action,
                "detail": result.detail,
            }
        )

    def write(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "started_at": self.started_at,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "certificate": self.certificate,
                    "providers": self.providers,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )



def required_env(name: str) -> str:
    value = os.getenv(name, "")
    value = value.replace("\r", "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value



def clean_bearer_secret(raw: str) -> str:
    value = raw.replace("\r", "").strip()
    lower = value.lower()
    if lower.startswith("bearer "):
        value = value.split(" ", 1)[1].strip()
    return value



def join_csv_str(items: list[str | int]) -> str:
    return ",".join(str(x) for x in items if str(x).strip())
