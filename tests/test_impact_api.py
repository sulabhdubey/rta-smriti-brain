import json
from contextlib import closing
from unittest.mock import patch
from test_passport_api import PassportApiTests
from rta_brain import console, db


class ImpactApiTests(PassportApiTests):
    def test_impact_is_authenticated_readonly_and_rejects_bad_action(self):
        import urllib.request
        import urllib.error
        def request(payload, token=True):
            headers = {"Content-Type": "application/json"}
            if token:
                headers["X-Rta-Smriti-Token"] = self.config.capability_token
            req = urllib.request.Request(self.url + "/api/impact", headers=headers,
                data=json.dumps({"db_path": str(self.path), "project": "atlas", "target": "missing", **payload}).encode())
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.load(response)
        with closing(db.connect(self.path)) as writer, patch.object(console, "_open_db", side_effect=AssertionError("write connector")):
            writer.execute("BEGIN IMMEDIATE")
            self.assertEqual(request({})["status"], "no_match")
            writer.rollback()
        for data, token, status in (({}, False, 403), ({"action": "publish"}, True, 400), ({"project": "foreign"}, True, 400)):
            with self.assertRaises(urllib.error.HTTPError) as error:
                request(data, token)
            self.assertEqual(error.exception.code, status)
