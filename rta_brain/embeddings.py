"""Optional, local-only embedding providers for hybrid retrieval."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Protocol


class EmbeddingProvider(Protocol):
    name: str
    model: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


@dataclass
class HashEmbeddingProvider:
    """A deterministic feature-hashing baseline with no external dependency."""

    dimensions: int = 256
    name: str = "hash"
    model: str = "rta-feature-hash-v1"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = re.findall(r"[a-z0-9_]+", text.lower())
        features = tokens + [f"{left}:{right}" for left, right in zip(tokens, tokens[1:])]
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


class SentenceTransformerEmbeddingProvider:
    """Lazy adapter for locally installed sentence-transformers models."""

    name = "sentence-transformers"

    def __init__(
        self,
        model: str = "all-MiniLM-L6-v2",
        *,
        local_files_only: bool = False,
    ) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is not installed; use the hash provider or install the optional package"
            ) from exc
        self.model = model
        self._model = SentenceTransformer(model, local_files_only=local_files_only)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self._model.encode(texts, normalize_embeddings=True)
        return [[float(value) for value in vector] for vector in vectors]


def create_provider(
    name: str,
    model: str | None = None,
    *,
    local_files_only: bool = False,
) -> EmbeddingProvider | None:
    normalized = (name or "none").strip().lower()
    if normalized == "none":
        return None
    if normalized == "hash":
        return HashEmbeddingProvider()
    if normalized == "sentence-transformers":
        return SentenceTransformerEmbeddingProvider(
            model or "all-MiniLM-L6-v2",
            local_files_only=local_files_only,
        )
    raise ValueError(f"unknown embedding provider: {name}")


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)
