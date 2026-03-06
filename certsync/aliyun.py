from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from alibabacloud_cas20200407 import models as cas_models
from alibabacloud_cas20200407.client import Client as CasClient
from alibabacloud_tea_openapi import models as open_api_models

from certsync.utils import ProviderResult, join_csv_str, required_env
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


class AliyunPublisher:
    def __init__(self, config: dict[str, Any]) -> None:
        access_key_id = required_env("ALIBABA_CLOUD_ACCESS_KEY_ID")
        access_key_secret = required_env("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

        openapi = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
        )
        openapi.endpoint = str(config.get("endpoint") or "cas.aliyuncs.com")
        self.client = CasClient(openapi)
        self.config = config

    def _fixed_cert_name(self) -> str:
        return str(self.config.get("certificate_name") or "jsw-ac-cn-zerossl").strip()

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

    def _list_uploaded_by_name(self, cert_name: str) -> list[dict[str, Any]]:
        req = cas_models.ListUserCertificateOrderRequest(
            order_type="UPLOAD",
            keyword=cert_name,
            show_size=100,
            current_page=1,
        )
        resp = self.client.list_user_certificate_order(req)
        body = resp.body.to_map() if hasattr(resp.body, "to_map") else {}

        items = body.get("CertificateOrderList") or body.get("certificateOrderList") or []

        out: list[dict[str, Any]] = []
        for item in items:
            name = str(item.get("Name") or item.get("name") or "").strip()
            if name != cert_name:
                continue

            cert_id = item.get("CertId") or item.get("certId")
            if cert_id is None:
                continue

            end_at_raw = (
                item.get("EndDate")
                or item.get("endDate")
                or item.get("EndTime")
                or item.get("endTime")
                or item.get("ExpireTime")
                or item.get("expireTime")
            )

            out.append(
                {
                    "cert_id": int(cert_id),
                    "name": name,
                    "expired": bool(item.get("Expired")),
                    "end_at_raw": end_at_raw,
                    "end_at": _parse_dt(end_at_raw),
                    "status": item.get("Status") or item.get("status"),
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
            expired = bool(item.get("expired"))
            end_at = item.get("end_at") or datetime.max.replace(tzinfo=timezone.utc)
            expired_rank = 0 if expired or end_at <= now else 1
            return (expired_rank, end_at)

        return sorted(items, key=sort_key)[0]

    def _delete_certificate(self, cert_id: int) -> None:
        req = cas_models.DeleteUserCertificateRequest(cert_id=cert_id)
        self.client.delete_user_certificate(req)

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
        cert_name = self._fixed_cert_name()

        remote_same_name = self._list_uploaded_by_name(cert_name)
        remote_same_expiry = self._find_same_expiry_remote(remote_same_name, target_expiry)

        # 只以“远端真的存在”为准，不再用 state 直接 skip
        if remote_same_expiry is not None:
            return ProviderResult(
                provider="aliyun",
                changed=False,
                action="skip",
                detail={
                    "reason": "same_name_same_expiry_remote_exists",
                    "cert_id": remote_same_expiry["cert_id"],
                    "cert_name": cert_name,
                    "deployed_not_after": target_expiry,
                    "cert_region": self.config.get("cert_region", "ap-southeast-1"),
                },
            )

        deleted_old: dict[str, Any] | None = None

        try:
            cert_id = self._upload_certificate(cert_name, fullchain_pem, private_key_pem)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "NameRepeat" not in msg or not self.config.get("delete_on_name_repeat", True):
                raise

            candidate = self._pick_delete_candidate(remote_same_name)
            if candidate is None:
                raise RuntimeError(
                    f"Aliyun returned NameRepeat for '{cert_name}', but no same-name uploaded certificate was found."
                ) from exc

            self._delete_certificate(candidate["cert_id"])
            deleted_old = candidate
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

                job_name = f"{cert_name}-deploy"
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
                "cert_region": self.config.get("cert_region", "ap-southeast-1"),
                "deleted_old": deleted_old,
                "jobs": jobs,
            },
        )
