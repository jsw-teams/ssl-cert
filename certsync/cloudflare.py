from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

from certsync.utils import ProviderResult, clean_bearer_secret, required_env
from certsync.x509util import CertificateMeta, extract_leaf_certificate, strip_ec_parameters


def _parse_cf_time(value: Any) -> datetime | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
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

    def _pick_earliest_expiring(self, items: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not items:
            return None

        now = datetime.now(timezone.utc)

        def sort_key(item: dict[str, Any]) -> tuple[int, datetime, datetime]:
            status = str(item.get("status") or "").lower()
            expires_on = _parse_cf_time(item.get("expires_on")) or datetime.max.replace(tzinfo=timezone.utc)
            uploaded_on = _parse_cf_time(item.get("uploaded_on")) or datetime.max.replace(tzinfo=timezone.utc)

            expired_rank = 0 if expires_on <= now else 1
            active_rank = 0 if status == "active" else 1
            return (expired_rank, active_rank, expires_on, uploaded_on)

        return sorted(items, key=sort_key)[0]

    def _split_candidates(
        self,
        existing_items: list[dict[str, Any]],
        wanted_hosts: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        wanted = self._norm_hosts(wanted_hosts)

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

        return exact, superset, overlap

    def _find_best_existing(
        self,
        existing_items: list[dict[str, Any]],
        wanted_hosts: list[str],
    ) -> tuple[dict[str, Any] | None, str]:
        exact, superset, overlap = self._split_candidates(existing_items, wanted_hosts)

        candidate = self._pick_earliest_expiring(exact)
        if candidate is not None:
            return candidate, "exact"

        candidate = self._pick_earliest_expiring(superset)
        if candidate is not None:
            return candidate, "superset"

        candidate = self._pick_earliest_expiring(overlap)
        if candidate is not None:
            return candidate, "overlap"

        return None, "none"

    def _find_uploaded_target(
        self,
        existing_items: list[dict[str, Any]],
        wanted_hosts: list[str],
        target_expiry: str,
        target_issuer: str,
    ) -> dict[str, Any] | None:
        wanted = sorted(self._norm_hosts(wanted_hosts))
        target_expiry_dt = _parse_cf_time(target_expiry)

        for item in existing_items:
            item_hosts = sorted(self._norm_hosts(item.get("hosts")))
            if item_hosts != wanted:
                continue

            item_expiry = _parse_cf_time(item.get("expires_on"))
            item_issuer = str(item.get("issuer") or "").strip()

            if item_expiry == target_expiry_dt and item_issuer == target_issuer:
                return item

        return None

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        msg = str(exc)
        return "code': 2005" in msg or '"code": 2005' in msg

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

        existing_items = self._list_existing()

        # state 丢失时，若 Cloudflare 已经是目标证书，也直接视为成功
        already = self._find_uploaded_target(existing_items, wanted_hosts, target_expiry, target_issuer)
        if already is not None:
            return ProviderResult(
                provider="cloudflare",
                changed=False,
                action="skip",
                detail={
                    "reason": "same_hosts_same_expiry_same_issuer_already_exists",
                    "custom_certificate_id": already.get("id"),
                    "hosts": wanted_hosts,
                    "deployed_not_after": target_expiry,
                    "deployed_issuer": target_issuer,
                },
            )

        patch_payload = {
            "certificate": extract_leaf_certificate(fullchain_pem),
            "private_key": strip_ec_parameters(private_key_pem),
            "bundle_method": self.config.get("bundle_method", "ubiquitous"),
        }

        create_payload = {
            **patch_payload,
            "type": self.config.get("certificate_type", "sni_custom"),
        }

        existing, match_mode = self._find_best_existing(existing_items, wanted_hosts)

        # 优先更新旧证书
        if existing is not None:
            cert_id = str(existing["id"])
            try:
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
            except Exception as exc:  # noqa: BLE001
                if not self._is_quota_error(exc):
                    raise

                # quota 之后立刻复查最终状态；若目标证书已存在，则按成功处理
                reloaded = self._list_existing()
                verified = self._find_uploaded_target(reloaded, wanted_hosts, target_expiry, target_issuer)
                if verified is not None:
                    return ProviderResult(
                        provider="cloudflare",
                        changed=True,
                        action="verified_after_quota_on_update",
                        detail={
                            "custom_certificate_id": verified.get("id"),
                            "matched_existing_id": cert_id,
                            "match_mode": match_mode,
                            "hosts": wanted_hosts,
                            "deployed_not_after": target_expiry,
                            "deployed_issuer": target_issuer,
                            "message": "Cloudflare returned quota error, but post-check confirms the target certificate is already present.",
                        },
                    )
                raise

        # 找不到旧证书时才创建
        try:
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
        except Exception as exc:  # noqa: BLE001
            if not self._is_quota_error(exc):
                raise

            reloaded = self._list_existing()
            verified = self._find_uploaded_target(reloaded, wanted_hosts, target_expiry, target_issuer)
            if verified is not None:
                return ProviderResult(
                    provider="cloudflare",
                    changed=True,
                    action="verified_after_quota_on_create",
                    detail={
                        "custom_certificate_id": verified.get("id"),
                        "match_mode": "created_new",
                        "hosts": wanted_hosts,
                        "deployed_not_after": target_expiry,
                        "deployed_issuer": target_issuer,
                        "message": "Cloudflare returned quota error, but post-check confirms the target certificate is already present.",
                    },
                )
            raise
