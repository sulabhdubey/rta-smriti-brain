import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rta_brain import db
from rta_brain.passport_demo import prepare_demo


class PassportDemoTests(unittest.TestCase):
    def test_demo_is_synthetic_isolated_and_does_not_overwrite_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = prepare_demo(root)
            with closing(db.connect(database)) as conn:
                names = [row[0] for row in conn.execute("SELECT name FROM projects ORDER BY name")]
                self.assertEqual(names, ["atlas-studio", "harbor-research"])
                db.save_checkpoint(conn, "atlas-studio", "My local edits")
            self.assertEqual(prepare_demo(root), database)
            with closing(db.connect_readonly(database)) as conn:
                self.assertEqual(db.latest_checkpoint(conn, "atlas-studio", initialize_schema=False)["objective"], "My local edits")

    def test_demo_refuses_nonempty_arbitrary_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep.txt").write_text("Do not change this folder")
            with self.assertRaises(ValueError):
                prepare_demo(root)
            self.assertEqual((root / "keep.txt").read_text(), "Do not change this folder")
