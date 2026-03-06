from __future__ import annotations

import argparse
import json
import sys

from certsync.config import load_config
from certsync.orchestrator import Orchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish renewed certificates to multiple clouds")
    parser.add_argument("--config", required=True, help="Path to config.yml")
    parser.add_argument("--fullchain", required=True, help="Path to fullchain PEM")
    parser.add_argument("--privkey", required=True, help="Path to private key PEM")
    parser.add_argument("--output", required=True, help="Path to JSON run report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config)
        result = Orchestrator(config).run(args.fullchain, args.privkey, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
