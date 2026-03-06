from __future__ import annotations

from typing import Any

from certsync.aliyun import AliyunPublisher
from certsync.cloudflare import CloudflarePublisher
from certsync.state import StateStore
from certsync.tencent import TencentPublisher
from certsync.utils import RunReport
from certsync.x509util import parse_certificate_meta, read_text


class Orchestrator:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        cert_cfg = config.get("cert") or {}
        self.state = StateStore(cert_cfg.get("state_file") or ".state/certsync-state.json")
        self.state.load()

    def run(self, fullchain_path: str, privkey_path: str, output_path: str) -> dict[str, Any]:
        fullchain_pem = read_text(fullchain_path)
        private_key_pem = read_text(privkey_path)
        meta = parse_certificate_meta(fullchain_pem)

        report = RunReport()
        report.certificate = {
            "subject": meta.subject,
            "issuer": meta.issuer,
            "serial_number": meta.serial_number,
            "not_before": meta.not_before.isoformat(),
            "not_after": meta.not_after.isoformat(),
            "sha256": meta.sha256,
            "san_dns_names": meta.san_dns_names,
        }

        providers: list[tuple[str, Any, dict[str, Any]]] = []
        if (self.config.get("cloudflare") or {}).get("enabled"):
            providers.append(("cloudflare", CloudflarePublisher(self.config["cloudflare"]), self.config["cloudflare"]))
        if (self.config.get("aliyun") or {}).get("enabled"):
            providers.append(("aliyun", AliyunPublisher(self.config["aliyun"]), self.config["aliyun"]))
        if (self.config.get("tencent") or {}).get("enabled"):
            providers.append(("tencent", TencentPublisher(self.config["tencent"]), self.config["tencent"]))

        for name, publisher, _cfg in providers:
            previous_state = self.state.get_provider(name)
            result = publisher.publish(fullchain_pem, private_key_pem, meta, previous_state)
            report.add(result)
            if result.changed:
                self.state.set_provider(name, result.detail)

        self.state.save()
        report.write(output_path)
        return {
            "certificate": report.certificate,
            "providers": report.providers,
            "state_file": str(self.state.path),
        }
