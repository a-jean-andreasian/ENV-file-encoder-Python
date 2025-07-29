# Usage:
#
# Normal run (cleans up):
# - python -m unittest tests.test_encoder
#
# Preserve files:
# - KEEP_RESULTS=true python -m unittest tests.test_encoder

import os
import unittest
import json
from encoder import FileEncoder


class TestFileEncoder(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.join(os.path.dirname(__file__), "files")
        os.makedirs(self.base_dir, exist_ok=True)

        self.master_key_path = os.path.join(self.base_dir, "master.key.test")
        with open(self.master_key_path, "w") as f:
            f.write("123")

        self.dummy_txt_path = os.path.join(self.base_dir, "dummy.txt")
        with open(self.dummy_txt_path, "w") as f:
            f.write("This is a dummy text file.")

        self.dummy_json_path = os.path.join(self.base_dir, "dummy.json")
        with open(self.dummy_json_path, "w") as f:
            json.dump({"text": "This is a dummy file for testing purposes."}, f)

        self.files = [
            self.dummy_txt_path,
            self.dummy_json_path
        ]

        self.encoder = FileEncoder(
            master_key_path=self.master_key_path,
            files_to_encode=self.files
        )

    def test_encode_files(self):
        self.encoder.encode()

        for file in self.files:
            self.assertTrue(os.path.exists(f"{file}.enc"))
            self.assertFalse(os.path.exists(file))

    def test_decode_files(self):
        self.encoder.encode()
        self.encoder.decode()

        for file in self.files:
            self.assertTrue(os.path.exists(file))
            self.assertFalse(os.path.exists(f"{file}.enc"))

    def tearDown(self):
        if os.getenv("KEEP_RESULTS", "").lower() == "true":
            print("[Info] KEEP_RESULTS=true -> Skipping cleanup.")
            return

        for path in [
            self.master_key_path,
            self.dummy_txt_path,
            self.dummy_json_path,
            f"{self.dummy_txt_path}.enc",
            f"{self.dummy_json_path}.enc",
            os.path.join(self.base_dir, "salt")
        ]:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()
