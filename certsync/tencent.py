from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.ssl.v20191205 import models, ssl_client

from certsync.utils import ProviderResult, required_env
from certsync.x509util import CertificateMeta


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    s2 = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s2).astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class TencentPublisher:
    def __init__(self, config: dict[str, Any]) -> None:
        secret_id = required_env("TENCENTCLOUD_SECRET_ID")
        secret_key = required_env("TENCENTCLOUD_SECRET_KEY")
        self.cred = credential.Credential(secret_id, secret_key)
        self.config = config

    def _client(self, region: str = "") -> ssl_client.SslClient:
        http_profile = HttpProfile()
        http_profile.endpoint = "ssl.tencentcloudapi.com"
        profile = ClientProfile()
        profile.httpProfile = http_profile
        return ssl_client.SslClient(self.cred, region, profile)

    def _fixed_alias(self) -> str:
        return str(self.config.get("alias_name") or "jsw-ac-cn-zerossl").strip()

    def _describe_same_alias(self, alias: str) -> list[dict[str, Any]]:
        req = models.DescribeCertificatesRequest()
        req.from_json_string(
            json.dumps(
                {
                    "SearchKey": alias,
                    "Limit": 100,
                    "Offset": 0,
                }
            )
        )
        resp = self._client("").DescribeCertificates(req)
        data = json.loads(resp.to_json_string())

        items = data.get("Certificates") or data.get("Response", {}).get("Certificates") or []
        out: list[dict[str, Any]] = []

        for item in items:
            item_alias = str(item.get("Alias") or item.get("alias") or "").strip()
            if item_alias != alias:
                continue

            cert_id = item.get("CertificateId") or item.get("certificateId")
            if not cert_id:
                continue

            end_raw = (
                item.get("EndTime")
                or item.get("endTime")
                or item.get("CertEndTime")
                or item.get("certEndTime")
                or item.get("ExpireTime")
                or item.get("expireTime")
            )

            out.append(
                {
                    "certificate_id": str(cert_id),
                    "alias": item_alias,
                    "status": item.get("Status") or item.get("status"),
                    "end_at_raw": end_raw,
                    "end_at": _parse_dt(end_raw),
                }
            )
        return out

    def _find_same_expiry_remote(self, items: list[dict[str, Any]], target_expiry: str) -> dict[str, Any] | None:
        target_dt = _parse_dt(target_expiry)
        if target_dt is None:
            return None

        for item in items:
            end_at = item.get("end_at")
            if end_at == target_dt:
                return item
        return None

    def _pick_delete_candidate(self, items: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not items:
            return None

        now = datetime.now(timezone.utc)

        def sort_key(item: dict[str, Any]) -> tuple[int, datetime]:
            end_at = item.get("end_at") or datetime.max.replace(tzinfo=timezone.utc)
            expired_rank = 0 if end_at <= now else 1
            return (expired_rank, end_at)

        return sorted(items, key=sort_key)[0]

    def _delete_certificate(self, certificate_id: str) -> None:
        req = models.DeleteCertificateRequest()
        req.from_json_string(json.dumps({"CertificateId": certificate_id}))
        self._client("").DeleteCertificate(req)

    def _upload_certificate(self, alias: str, fullchain_pem: str, private_key_pem: str) -> tuple[str, str]:
        req = models.UploadCertificateRequest()
        req.from_json_string(
            json.dumps(
                {
                    "CertificatePublicKey": fullchain_pem,
                    "CertificatePrivateKey": private_key_pem,
                    "CertificateType": "SVR",
                    "Alias": alias,
                    "ProjectId": int(self.config.get("project_id", 0) or 0),
                    "Repeatable": False,
                }
            )
        )
        resp = self._client("").UploadCertificate(req)
        return resp.CertificateId, getattr(resp, "RepeatCertId", "") or ""

    def _deploy(self, certificate_id: str, resource: dict[str, Any]) -> dict[str, Any]:
        region = str(resource.get("region") or "")
        payload: dict[str, Any] = {
            "CertificateId": certificate_id,
            "ResourceType": resource["resource_type"],
            "InstanceIdList": list(resource.get("instance_id_list") or []),
        }
        if resource.get("status") is not None:
            payload["Status"] = int(resource["status"])
        if resource.get("is_cache") is not None:
            payload["IsCache"] = int(resource["is_cache"])

        req = models.DeployCertificateInstanceRequest()
        req.from_json_string(json.dumps(payload))
        resp = self._client(region).DeployCertificateInstance(req)
        return {
            "resource_type": resource["resource_type"],
            "region": region,
            "instance_id_list": payload["InstanceIdList"],
            "deploy_record_id": resp.DeployRecordId,
            "deploy_status": resp.DeployStatus,
        }

    def publish(
        self,
        fullchain_pem: str,
        private_key_pem: str,
        meta: CertificateMeta,
        previous_state: dict[str, Any],
    ) -> ProviderResult:
        target_expiry = meta.not_after.isoformat()
        alias = self._fixed_alias()

        remote_same_alias = self._describe_same_alias(alias)
        remote_same_expiry = self._find_same_expiry_remote(remote_same_alias, target_expiry)

        if remote_same_expiry is not None:
            return ProviderResult(
                provider="tencent",
                changed=False,
                action="skip",
                detail={
                    "reason": "same_alias_same_expiry_remote_exists",
                    "certificate_id": remote_same_expiry["certificate_id"],
                    "alias": alias,
                    "deployed_not_after": target_expiry,
                },
            )

        deleted_old: dict[str, Any] | None = None

        try:
            certificate_id, repeat_cert_id = self._upload_certificate(alias, fullchain_pem, private_key_pem)
        except Exception as exc:  # noqa: BLE001
            if not self.config.get("delete_on_alias_conflict", True):
                raise

            candidate = self._pick_delete_candidate(remote_same_alias)
            if candidate is None:
                raise

            self._delete_certificate(candidate["certificate_id"])
            deleted_old = candidate
            certificate_id, repeat_cert_id = self._upload_certificate(alias, fullchain_pem, private_key_pem)

        deployments: list[dict[str, Any]] = []
        deploy_cfg = self.config.get("deploy") or {}
        if deploy_cfg.get("enabled"):
            for item in deploy_cfg.get("resources") or []:
                if not item.get("instance_id_list"):
                    continue
                deployments.append(self._deploy(certificate_id, item))

        return ProviderResult(
            provider="tencent",
            changed=True,
            action="upload_and_deploy" if deployments else "upload",
            detail={
                "certificate_id": certificate_id,
                "repeat_cert_id": repeat_cert_id,
                "alias": alias,
                "deployed_not_after": target_expiry,
                "deleted_old": deleted_old,
                "deployments": deployments,
            },
        )
