from __future__ import annotations

import json
from typing import Any

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.ssl.v20191205 import models, ssl_client

from certsync.utils import ProviderResult, required_env
from certsync.x509util import CertificateMeta


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
        if previous_state.get("deployed_not_after") == target_expiry:
            return ProviderResult(
                provider="tencent",
                changed=False,
                action="skip",
                detail={"reason": "same_expiry", "deployed_not_after": target_expiry},
            )

        alias_prefix = str(self.config.get("alias_prefix") or "jsw-ac-cn-zerossl")
        alias = f"{alias_prefix}-{meta.not_after.strftime('%Y%m%d')}-{meta.sha256[:12]}"
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
                "deployments": deployments,
            },
        )
