from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

from certsync.utils import ProviderResult, clean_bearer_secret, required_env
from certsync.x509util import CertificateMeta, extract_leaf_certificate, strip_ec_parameters


def _parse_cf_time(value: Any) -> datetime | None:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Cloudflare 常见格式：2026-06-04T23:59:59Z
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except ValueError:
        return None


class CloudflarePublisher:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.zone_id = str(config.get("zone_id") or "").strip() or required_env("CF_EDGE_ZONE_ID")
        token = clean_bearer_secret(required_env("CF_EDGE_API_TOKEN"))

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/custom_certificates"

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        resp = self.session.request(method, url, timeout=60, **kwargs)
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"Cloudflare API returned non-JSON response: status={resp.status_code}, body={resp.text}"
            ) from exc

        if not resp.ok or not data.get("success"):
            raise RuntimeError(f"Cloudflare API error: {data}")
        return data

    @staticmethod
    def _norm_hosts(hosts: list[str] | None) -> set[str]:
        out: set[str] = set()
        for h in hosts or []:
            s = str(h).strip().lower()
            if s:
                out.add(s)
        return out

    def _list_existing(self) -> list[dict[str, Any]]:
        data = self._request("GET", self.base_url)
        return list(data.get("result") or [])

    def _pick_by_expiry(
        self,
        items: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not items:
            return None

        def sort_key(item: dict[str, Any]) -> tuple[int, datetime, datetime]:
            # active 优先；expires_on 越早越优先；uploaded_on 越早越优先
            status = str(item.get("status") or "").lower()
            active_rank = 0 if status == "active" else 1

            expires_on = _parse_cf_time(item.get("expires_on")) or datetime.max.replace(tzinfo=timezone.utc)
            uploaded_on = _parse_cf_time(item.get("uploaded_on")) or datetime.max.replace(tzinfo=timezone.utc)
            return (active_rank, expires_on, uploaded_on)

        return sorted(items, key=sort_key)[0]

    def _find_best_existing(self, hosts: list[str]) -> tuple[dict[str, Any] | None, str]:
        """
        先按 hosts 过滤，再按 expires_on 最早优先。

        选择顺序：
        1. exact: 现有 hosts 与目标 hosts 完全一致
        2. superset: 现有 hosts 覆盖目标 hosts
        3. overlap: 与目标 hosts 有交集
        """
        wanted = self._norm_hosts(hosts)
        if not wanted:
            return None, "none"

        existing_items = self._list_existing()

        exact: list[dict[str, Any]] = []
        superset: list[dict[str, Any]] = []
        overlap: list[dict[str, Any]] = []

        for item in existing_items:
            existing_hosts = self._norm_hosts(item.get("hosts"))
            if not existing_hosts:
                continue

            if existing_hosts == wanted:
                exact.append(item)
            elif wanted.issubset(existing_hosts):
                superset.append(item)
            elif wanted & existing_hosts:
                overlap.append(item)

        candidate = self._pick_by_expiry(exact)
        if candidate is not None:
            return candidate, "exact"

        candidate = self._pick_by_expiry(superset)
        if candidate is not None:
            return candidate, "superset"

        candidate = self._pick_by_expiry(overlap)
        if candidate is not None:
            return candidate, "overlap"

        return None, "none"

    def publish(
        self,
        fullchain_pem: str,
        private_key_pem: str,
        meta: CertificateMeta,
        previous_state: dict[str, Any],
    ) -> ProviderResult:
        target_expiry = meta.not_after.isoformat()
        target_issuer = meta.issuer

        wanted_hosts = list(self.config.get("hosts") or [])
        if not wanted_hosts:
            wanted_hosts = meta.san_dns_names

        # 只有“到期时间 + issuer + hosts”都相同，才真的跳过
        if (
            previous_state.get("deployed_not_after") == target_expiry
            and previous_state.get("deployed_issuer") == target_issuer
            and sorted(previous_state.get("hosts") or []) == sorted(wanted_hosts)
        ):
            return ProviderResult(
                provider="cloudflare",
                changed=False,
                action="skip",
                detail={
                    "reason": "same_expiry_issuer_hosts",
                    "deployed_not_after": target_expiry,
                    "deployed_issuer": target_issuer,
                    "hosts": wanted_hosts,
                },
            )

        # PATCH 时不强行传 type，避免旧资源类型不一致带来兼容问题
        patch_payload = {
            "certificate": extract_leaf_certificate(fullchain_pem),
            "private_key": strip_ec_parameters(private_key_pem),
            "bundle_method": self.config.get("bundle_method", "ubiquitous"),
        }

        create_payload = {
            **patch_payload,
            "type": self.config.get("certificate_type", "sni_custom"),
        }

        existing, match_mode = self._find_best_existing(wanted_hosts)

        # 优先 PATCH 已有旧证书（哪怕旧 issuer 是 Google）
        if existing is not None:
            cert_id = existing["id"]
            result = self._request("PATCH", f"{self.base_url}/{cert_id}", json=patch_payload)["result"]
            return ProviderResult(
                provider="cloudflare",
                changed=True,
                action="update",
                detail={
                    "custom_certificate_id": result.get("id", cert_id),
                    "matched_existing_id": cert_id,
                    "match_mode": match_mode,
                    "matched_existing_issuer": existing.get("issuer"),
                    "matched_existing_expires_on": existing.get("expires_on"),
                    "hosts": wanted_hosts,
                    "deployed_not_after": target_expiry,
                    "deployed_issuer": target_issuer,
                },
            )

        # 完全找不到候选时才创建
        result = self._request("POST", self.base_url, json=create_payload)["result"]
        return ProviderResult(
            provider="cloudflare",
            changed=True,
            action="create",
            detail={
                "custom_certificate_id": result.get("id"),
                "match_mode": "created_new",
                "hosts": wanted_hosts,
                "deployed_not_after": target_expiry,
                "deployed_issuer": target_issuer,
            },
        )
