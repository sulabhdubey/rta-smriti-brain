import sys
import types
import unittest
from unittest.mock import Mock, patch

from rta_brain.embeddings import SentenceTransformerEmbeddingProvider


class EmbeddingSecurityTests(unittest.TestCase):
    def test_sentence_transformer_read_path_loads_local_files_only(self):
        constructor = Mock()
        module = types.SimpleNamespace(SentenceTransformer=constructor)
        with patch.dict(sys.modules, {"sentence_transformers": module}):
            provider = SentenceTransformerEmbeddingProvider(
                "local-model", local_files_only=True
            )
        constructor.assert_called_once_with("local-model", local_files_only=True)
        self.assertEqual(provider.model, "local-model")


if __name__ == "__main__":
    unittest.main()
