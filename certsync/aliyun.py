from __future__ import annotations

from typing import Any

from alibabacloud_cas20200407 import models as cas_models
from alibabacloud_cas20200407.client import Client as CasClient
from alibabacloud_tea_openapi import models as open_api_models

from certsync.utils import ProviderResult, join_csv_str, required_env
from certsync.x509util import CertificateMeta


class AliyunPublisher:
    def __init__(self, config: dict[str, Any]) -> None:
        access_key_id = required_env("ALIBABA_CLOUD_ACCESS_KEY_ID")
        access_key_secret = required_env("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

        openapi = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
        )
        openapi.endpoint = "cas.aliyuncs.com"
        self.client = CasClient(openapi)
        self.config = config

    def _upload_certificate(self, cert_name: str, fullchain_pem: str, private_key_pem: str) -> int:
        req = cas_models.UploadUserCertificateRequest(
            name=cert_name,
            cert=fullchain_pem,
            key=private_key_pem,
        )
        resp = self.client.upload_user_certificate(req)
        cert_id = getattr(resp.body, "cert_id", None)
        if cert_id is None:
            raise RuntimeError("Aliyun upload_user_certificate returned no cert_id")
        return int(cert_id)

    def _create_deployment_job(
        self,
        name: str,
        cert_id: int,
        resource_ids: list[str | int],
        contact_ids: list[str | int],
        schedule_time: str | int | None,
    ) -> int:
        req = cas_models.CreateDeploymentJobRequest(
            name=name,
            job_type="user",
            cert_ids=str(cert_id),
            resource_ids=join_csv_str(resource_ids),
            contact_ids=join_csv_str(contact_ids),
        )
        if schedule_time not in (None, ""):
            req.schedule_time = int(schedule_time)
        resp = self.client.create_deployment_job(req)
        job_id = getattr(resp.body, "job_id", None)
        if job_id is None:
            raise RuntimeError("Aliyun create_deployment_job returned no job_id")
        return int(job_id)

    def _activate_deployment_job(self, job_id: int) -> None:
        req = cas_models.UpdateDeploymentJobStatusRequest(job_id=job_id, status="pending")
        self.client.update_deployment_job_status(req)

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
                provider="aliyun",
                changed=False,
                action="skip",
                detail={"reason": "same_expiry", "deployed_not_after": target_expiry},
            )

        prefix = str(self.config.get("certificate_name_prefix") or "jsw-ac-cn-zerossl")
        cert_name = f"{prefix}-{meta.not_after.strftime('%Y%m%d')}-{meta.sha256[:12]}"
        cert_id = self._upload_certificate(cert_name, fullchain_pem, private_key_pem)

        jobs: list[dict[str, Any]] = []
        deploy_cfg = self.config.get("deploy") or {}
        if deploy_cfg.get("enabled"):
            contact_ids = list(deploy_cfg.get("contact_ids") or [])
            if not contact_ids:
                raise RuntimeError("Aliyun deploy.enabled=true requires deploy.contact_ids")
            for item in deploy_cfg.get("resources") or []:
                resource_ids = list(item.get("resource_ids") or [])
                if not resource_ids:
                    continue
                job_name = (
                    f"{prefix}-{item.get('cloud_name', 'aliyun')}-"
                    f"{item.get('cloud_product', 'resource')}-{meta.not_after.strftime('%Y%m%d')}"
                )
                job_id = self._create_deployment_job(
                    name=job_name,
                    cert_id=cert_id,
                    resource_ids=resource_ids,
                    contact_ids=contact_ids,
                    schedule_time=deploy_cfg.get("schedule_time"),
                )
                self._activate_deployment_job(job_id)
                jobs.append(
                    {
                        "job_id": job_id,
                        "cloud_name": item.get("cloud_name"),
                        "cloud_product": item.get("cloud_product"),
                        "resource_ids": resource_ids,
                    }
                )

        return ProviderResult(
            provider="aliyun",
            changed=True,
            action="upload_and_deploy" if jobs else "upload",
            detail={
                "cert_id": cert_id,
                "cert_name": cert_name,
                "deployed_not_after": target_expiry,
                "jobs": jobs,
            },
        )
