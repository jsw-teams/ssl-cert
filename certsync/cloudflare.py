from __future__ import annotations

from typing import Any

import requests

from certsync.utils import ProviderResult, clean_bearer_secret, required_env
from certsync.x509util import CertificateMeta, extract_leaf_certificate, strip_ec_parameters


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
        data = resp.json()
        if not resp.ok or not data.get("success"):
            raise RuntimeError(f"Cloudflare API error: {data}")
        return data

    def _find_existing(self, hosts: list[str]) -> dict[str, Any] | None:
        data = self._request("GET", self.base_url)
        wanted = set(hosts)
        for item in data.get("result", []):
            existing_hosts = set(item.get("hosts") or [])
            if wanted.issubset(existing_hosts):
                return item
        return None

    def publish(
        self,
        fullchain_pem: str,
        private_key_pem: str,
        meta: CertificateMeta,
        previous_state: dict[str, Any],
    ) -> ProviderResult:
        wanted_hosts = list(self.config.get("hosts") or [])
        if not wanted_hosts:
            wanted_hosts = meta.san_dns_names

        target_expiry = meta.not_after.isoformat()
        if previous_state.get("deployed_not_after") == target_expiry:
            return ProviderResult(
                provider="cloudflare",
                changed=False,
                action="skip",
                detail={"reason": "same_expiry", "deployed_not_after": target_expiry},
            )

        payload = {
            "certificate": extract_leaf_certificate(fullchain_pem),
            "private_key": strip_ec_parameters(private_key_pem),
            "bundle_method": self.config.get("bundle_method", "ubiquitous"),
            "type": self.config.get("certificate_type", "sni_custom"),
        }

        existing = self._find_existing(wanted_hosts)
        if existing:
            cert_id = existing["id"]
            result = self._request("PATCH", f"{self.base_url}/{cert_id}", json=payload)["result"]
            return ProviderResult(
                provider="cloudflare",
                changed=True,
                action="update",
                detail={
                    "custom_certificate_id": result.get("id", cert_id),
                    "hosts": wanted_hosts,
                    "deployed_not_after": target_expiry,
                },
            )

        result = self._request("POST", self.base_url, json=payload)["result"]
        return ProviderResult(
            provider="cloudflare",
            changed=True,
            action="create",
            detail={
                "custom_certificate_id": result.get("id"),
                "hosts": wanted_hosts,
                "deployed_not_after": target_expiry,
            },
        )
