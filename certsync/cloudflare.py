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

            # 已过期优先；active 再优先；之后最早到期优先
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

    def _pick_delete_candidate_for_quota(
        self,
        existing_items: list[dict[str, Any]],
        wanted_hosts: list[str],
    ) -> tuple[dict[str, Any] | None, str]:
        """
        quota 触发时，只删除和目标 hosts 相关的旧证书。
        不删除无关证书，避免误伤其他域名。
        """
        return self._find_best_existing(existing_items, wanted_hosts)

    @staticmethod
    def _is_same_target_cert(
        item: dict[str, Any],
        wanted_hosts: list[str],
        target_expiry: str,
        target_issuer: str,
    ) -> bool:
        item_hosts = sorted([str(x).strip().lower() for x in (item.get("hosts") or []) if str(x).strip()])
        wanted = sorted([str(x).strip().lower() for x in wanted_hosts if str(x).strip()])
        item_expiry = str(item.get("expires_on") or "").replace("Z", "+00:00")
        target_expiry_norm = str(target_expiry).replace("Z", "+00:00")
        item_issuer = str(item.get("issuer") or "").strip()
        return item_hosts == wanted and item_expiry == target_expiry_norm and item_issuer == target_issuer

    def _delete_certificate(self, custom_certificate_id: str) -> None:
        self._request("DELETE", f"{self.base_url}/{custom_certificate_id}")

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

        # state 命中时直接跳过
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

        # 即使 state 丢了，只要 Cloudflare 已经有同目标证书，也直接跳过
        for item in existing_items:
            if self._is_same_target_cert(item, wanted_hosts, target_expiry, target_issuer):
                return ProviderResult(
                    provider="cloudflare",
                    changed=False,
                    action="skip",
                    detail={
                        "reason": "same_hosts_same_expiry_same_issuer_already_exists",
                        "custom_certificate_id": item.get("id"),
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
        deleted_old: dict[str, Any] | None = None

        # 1) 优先更新已有旧证书（哪怕旧 issuer 是 Google）
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
                        "deleted_old": None,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                # PATCH 也可能因 quota 失败；此时删掉这一张旧目标证书，再创建新证书
                if ("code': 2005" in msg or '"code": 2005' in msg) and self.config.get("delete_on_quota", True):
                    self._delete_certificate(cert_id)
                    deleted_old = {
                        "custom_certificate_id": cert_id,
                        "issuer": existing.get("issuer"),
                        "expires_on": existing.get("expires_on"),
                        "hosts": existing.get("hosts"),
                        "reason": "quota_reached_on_patch",
                    }
                    result = self._request("POST", self.base_url, json=create_payload)["result"]
                    return ProviderResult(
                        provider="cloudflare",
                        changed=True,
                        action="delete_old_and_create",
                        detail={
                            "custom_certificate_id": result.get("id"),
                            "match_mode": match_mode,
                            "hosts": wanted_hosts,
                            "deployed_not_after": target_expiry,
                            "deployed_issuer": target_issuer,
                            "deleted_old": deleted_old,
                        },
                    )
                raise

        # 2) 完全找不到相关旧证书时，才尝试创建
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
                    "deleted_old": None,
                },
            )
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if ("code': 2005" in msg or '"code": 2005' in msg) and self.config.get("delete_on_quota", True):
                candidate, candidate_mode = self._pick_delete_candidate_for_quota(existing_items, wanted_hosts)
                if candidate is None:
                    raise RuntimeError(
                        "Cloudflare quota reached, and no related old custom certificate was found to delete safely."
                    ) from exc

                cert_id = str(candidate["id"])
                self._delete_certificate(cert_id)
                deleted_old = {
                    "custom_certificate_id": cert_id,
                    "issuer": candidate.get("issuer"),
                    "expires_on": candidate.get("expires_on"),
                    "hosts": candidate.get("hosts"),
                    "reason": "quota_reached_on_create",
                }
                result = self._request("POST", self.base_url, json=create_payload)["result"]
                return ProviderResult(
                    provider="cloudflare",
                    changed=True,
                    action="delete_old_and_create",
                    detail={
                        "custom_certificate_id": result.get("id"),
                        "match_mode": candidate_mode,
                        "hosts": wanted_hosts,
                        "deployed_not_after": target_expiry,
                        "deployed_issuer": target_issuer,
                        "deleted_old": deleted_old,
                    },
                )
            raise
