"""Stable local Python SDK facade for Rta-Smriti v1.0 read contracts."""

from __future__ import annotations

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


SDK_CONTRACT_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class BrainClient:
    """Open a fresh hardened connection for each bounded SDK operation."""

    database: Path
    project: str
    root: Path | None = None

    def _path(self) -> Path:
        return Path(self.database).expanduser().resolve()

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
