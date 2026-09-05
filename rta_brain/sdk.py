"""Stable local Python SDK facade for Rta-Smriti v1.0 read contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cognition import cognition_snapshot
from .context_host import compile_context_for_agent
from .db import connect, doctor, integrity_diagnostics, search
from .diagnostics import retrieval_diagnostics
from .multimodal import (
    export_multimodal_manifest,
    list_multimodal_derivations,
    list_multimodal_evidence,
    verify_multimodal_source,
)
from .temporal import truth_current, truth_explain, truth_history
from .trusted_lifecycle import (
    apply_lifecycle,
    inspect_lifecycle,
    lifecycle_review_bundle,
    plan_lifecycle,
    plan_remove_lifecycle,
    plan_repair_lifecycle,
    plan_stop_lifecycle,
    remove_lifecycle,
    repair_lifecycle,
    stop_lifecycle,
    verify_lifecycle,
)

SDK_CONTRACT_VERSION = "1.0"


def _public_lifecycle_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"backup_path", "receipt_path"}
    }


@dataclass(frozen=True, slots=True)
class BrainClient:
    """Open a fresh hardened connection for each bounded SDK operation."""

    database: Path
    project: str
    root: Path | None = None
    sessions_root: Path | None = None

    def _path(self) -> Path:
        return Path(self.database).expanduser().resolve()

    def _lifecycle_request(self) -> dict[str, Any]:
        if self.root is None:
            raise ValueError("lifecycle operations require an exact canonical root")
        database = self._path()
        return {
            "tool_root": Path(__file__).resolve().parents[1],
            "brain_dir": database.parent,
            "db_path": database,
            "project": self.project,
            "root": Path(self.root).expanduser().resolve(),
            "sessions_root": (
                Path(self.sessions_root).expanduser().resolve()
                if self.sessions_root is not None
                else None
            ),
        }

    def lifecycle_inspect(self) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **inspect_lifecycle(self._lifecycle_request()),
        }

    def lifecycle_plan(
        self, desired_state: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **plan_lifecycle(self._lifecycle_request(), desired_state),
        }

    def lifecycle_apply(
        self,
        desired_state: Mapping[str, Any],
        *,
        plan_digest: str,
        observed_state_digest: str,
    ) -> dict[str, Any]:
        plan = plan_lifecycle(self._lifecycle_request(), desired_state)
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **_public_lifecycle_result(
                apply_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan_digest,
                        "observed_state_digest": observed_state_digest,
                    },
                )
            ),
        }

    def lifecycle_verify(self, proof_level: str = "process") -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **verify_lifecycle(self._lifecycle_request(), proof_level),
        }

    def lifecycle_plan_repair(self) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **plan_repair_lifecycle(self._lifecycle_request()),
        }

    def lifecycle_repair(
        self,
        *,
        plan_digest: str,
        desired_state_digest: str,
        observed_state_digest: str,
    ) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **_public_lifecycle_result(
                repair_lifecycle(
                    self._lifecycle_request(),
                    {
                        "approved": True,
                        "plan_digest": plan_digest,
                        "desired_state_digest": desired_state_digest,
                        "observed_state_digest": observed_state_digest,
                    },
                )
            ),
        }

    def lifecycle_plan_stop(self) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **plan_stop_lifecycle(self._lifecycle_request()),
        }

    def lifecycle_stop(
        self, *, plan_digest: str, observed_state_digest: str
    ) -> dict[str, Any]:
        plan = plan_stop_lifecycle(self._lifecycle_request())
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **_public_lifecycle_result(
                stop_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan_digest,
                        "observed_state_digest": observed_state_digest,
                    },
                )
            ),
        }

    def lifecycle_plan_remove(self) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **plan_remove_lifecycle(self._lifecycle_request()),
        }

    def lifecycle_remove(
        self, *, plan_digest: str, observed_state_digest: str
    ) -> dict[str, Any]:
        plan = plan_remove_lifecycle(self._lifecycle_request())
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **_public_lifecycle_result(
                remove_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan_digest,
                        "observed_state_digest": observed_state_digest,
                    },
                )
            ),
        }

    def lifecycle_review(self, *, receipt_limit: int = 200) -> dict[str, Any]:
        return {
            "contract_version": SDK_CONTRACT_VERSION,
            **lifecycle_review_bundle(
                self._lifecycle_request(), receipt_limit=receipt_limit
            ),
        }

    def health(self) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **doctor(conn),
            }
        finally:
            conn.close()

    def search(self, query: str, *, limit: int = 8) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **search(conn, query, project=self.project, limit=limit),
            }
        finally:
            conn.close()

    def retrieval_diagnostics(
        self, query: str, *, limit: int = 8
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **retrieval_diagnostics(
                    conn, query, project=self.project, limit=limit
                ),
            }
        finally:
            conn.close()

    def cognition(
        self, *, include_change_impact: bool = True
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return cognition_snapshot(
                conn,
                project=self.project,
                active_root=self.root,
                include_change_impact=include_change_impact,
            )
        finally:
            conn.close()

    def truth_current(
        self, claim_id: str, *, valid_at: str | None = None
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **truth_current(
                    conn, project=self.project, claim_id=claim_id, valid_at=valid_at
                ),
            }
        finally:
            conn.close()

    def truth_explain(
        self, claim_id: str, *, valid_at: str | None = None
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **truth_explain(
                    conn, project=self.project, claim_id=claim_id, valid_at=valid_at
                ),
            }
        finally:
            conn.close()

    def truth_history(self, claim_id: str, *, limit: int = 500) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **truth_history(
                    conn, project=self.project, claim_id=claim_id, limit=limit
                ),
            }
        finally:
            conn.close()

    def compile_context(
        self,
        *,
        task_contract_id: int,
        principal_id: str,
        session_id: str,
        variant: str = "primary",
    ) -> dict[str, Any]:
        if self.root is None:
            raise ValueError("context compilation requires an exact canonical root")
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **compile_context_for_agent(
                    conn,
                    db_path=self._path(),
                    project=self.project,
                    active_root=self.root,
                    task_contract_id=task_contract_id,
                    principal_id=principal_id,
                    session_id=session_id,
                    variant_id=variant,
                ),
            }
        finally:
            conn.close()

    def integrity(self) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **integrity_diagnostics(
                    conn, project=self.project, active_root=self.root
                ),
            }
        finally:
            conn.close()

    def multimodal_derivations(
        self, source_id: str, *, include_text: bool = False, limit: int = 100
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **list_multimodal_derivations(
                    conn, project=self.project, source_id=source_id,
                    include_text=include_text, limit=limit,
                ),
            }
        finally:
            conn.close()

    def verify_media(self, source_id: str) -> dict[str, Any]:
        if self.root is None:
            raise ValueError("media verification requires an exact canonical root")
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **verify_multimodal_source(
                    conn, project=self.project, active_root=self.root,
                    source_id=source_id,
                ),
            }
        finally:
            conn.close()

    def export_media_manifest(
        self, *, audience: str = "local", limit: int = 1000
    ) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **export_multimodal_manifest(
                    conn, project=self.project, audience=audience, limit=limit
                ),
            }
        finally:
            conn.close()

    def multimodal(self, *, limit: int = 100) -> dict[str, Any]:
        conn = connect(self._path())
        try:
            return {
                "contract_version": SDK_CONTRACT_VERSION,
                **list_multimodal_evidence(
                    conn, project=self.project, limit=limit
                ),
            }
        finally:
            conn.close()
