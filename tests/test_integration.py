from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from shutil import rmtree
from subprocess import run
from unittest import TestCase
from unittest import main as unittest_main

from fv import (
    FVException,
    acquire_lock,
    decrypt_file,
    encrypt_file,
    get_index,
    release_lock,
    retrieve_file,
    sha256sum,
    store_file,
)

TESTING_DIR = "fv_testing_dir_947f6128-4d75-40bb-a9ad-1a64342bd860"


class FVTest(TestCase):
    def _clean_test_dir(self):
        try:
            rmtree(TESTING_DIR)
        except OSError:
            pass

    def setUp(self):
        self._clean_test_dir()
        Path(TESTING_DIR).mkdir()

    def tearDown(self):
        self._clean_test_dir()

    def test_sha256(self):
        with Path(f"{TESTING_DIR}/test_mdr1.txt").open("w") as f:
            f.write("I am a goofy file")
        self.assertEqual(
            sha256sum(f"{TESTING_DIR}/test_mdr1.txt"),
            "076dd4d0add0c2ce14af7579551fea579f7671ee1668421c12f080b5f25af1d2",
        )

    def test_encrypt_decrypt(self):
        """Quick and dirty because re-encrypting doesn't guarantee the same output, just encrypt and decrypt again"""
        with Path(f"{TESTING_DIR}/test_mdr1.txt").open("w") as f:
            f.write("I am a goofy file")
        encrypt_file(f"{TESTING_DIR}/test_mdr1.txt", "stoopid-Password-0")
        Path(f"{TESTING_DIR}/test_mdr1.txt").unlink()
        decrypt_file(f"{TESTING_DIR}/test_mdr1.txt.gpg", "stoopid-Password-0")
        with Path(f"{TESTING_DIR}/test_mdr1.txt").open() as f:
            o = f.read()
        assert o == "I am a goofy file"

    def test_try_encrypt_unacceptable_password(self):
        with Path(f"{TESTING_DIR}/test_mdr1.txt").open("w") as f:
            f.write("I am a goofy file")
        with self.assertRaises(FVException):
            encrypt_file(f"{TESTING_DIR}/test_mdr1.txt", 'stoopid-password-"')

    def test_can_get_hex_index(self):
        Path(f"{TESTING_DIR}/index").mkdir()
        with Path(f"{TESTING_DIR}/index/00a200030004000a.json").open("w") as f:
            f.write(dumps({"I am": "an index"}))
        self.assertEqual(get_index(f"{TESTING_DIR}"), (45598959112290314, {"I am": "an index"}))

    def test_cant_double_aquire(self):
        acquire_lock(TESTING_DIR)
        with self.assertRaises(FVException):
            acquire_lock(TESTING_DIR)

    def test_can_acquire_release_acquire_release(self):
        acquire_lock(TESTING_DIR)
        release_lock(TESTING_DIR)
        acquire_lock(TESTING_DIR)
        release_lock(TESTING_DIR)

    def test_cant_store_while_locked(self):
        with Path(f"{TESTING_DIR}/file.txt").open("w") as f:
            f.write("test content")
        acquire_lock(f"{TESTING_DIR}/store")
        with self.assertRaises(FVException):
            store_file(f"{TESTING_DIR}/store", f"{TESTING_DIR}/file.txt")

    def test_cant_retrieve_while_locked(self):
        acquire_lock(f"{TESTING_DIR}/store")
        with self.assertRaises(FVException):
            retrieve_file(f"{TESTING_DIR}/store", "42")

    def _load_a_file(self, file_name, file_content):
        with Path(f"{TESTING_DIR}/{file_name}").open("w") as f:
            f.write(file_content)
        store_file(f"{TESTING_DIR}/store", f"{TESTING_DIR}/{file_name}")
        return sha256(file_content.encode("utf-8")).hexdigest()

    def test_load_1_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file")
        with Path(f"{TESTING_DIR}/store/index/0000000000000001.json").open() as f:
            index = loads(f.read())
        self.assertEqual(type(index), dict)
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 6)])
        entry = next(iter(index.values()))
        self.assertEqual(entry[1], file_1_sum)  # Check original file sha256 from index
        self.assertEqual(entry[3], "file.txt")  # Check filename
        self.assertIsInstance(entry[4], int)  # padding_before
        self.assertIsInstance(entry[5], int)  # real_size
        # Note: stored file in /files/ has original content, encrypted file has padding
        assert all(p.name.endswith(".gpg") for p in Path(f"{TESTING_DIR}/store/encrypted_files").iterdir())

    def test_load_2_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file")
        with Path(f"{TESTING_DIR}/store/index/0000000000000002.json").open() as f:
            index = loads(f.read())
        self.assertEqual(type(index), dict)
        self.assertEqual(len(index), 2)
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 6), (36, 6)])
        values = list(index.values())
        self.assertEqual((values[0][1], values[0][3]), (file_1_sum, "file_1.txt"))
        self.assertEqual((values[1][1], values[1][3]), (file_2_sum, "file_2.txt"))
        # Check padding info exists
        for v in values:
            self.assertIsInstance(v[4], int)  # padding_before
            self.assertIsInstance(v[5], int)  # real_size
        assert all(p.name.endswith(".gpg") for p in Path(f"{TESTING_DIR}/store/encrypted_files").iterdir())

    def test_load_and_retrieve_a_cached_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file")
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        self.assertEqual(len(files), 1)
        retrieve_file(f"{TESTING_DIR}/store", files[0])
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 1)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), file_1_sum)

    def test_load_and_retrieve_2_cached_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file")
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        self.assertEqual(len(files), 2)
        retrieve_file(f"{TESTING_DIR}/store", files[0])
        retrieve_file(f"{TESTING_DIR}/store", files[1])
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 2)
        the_set = {sha256sum(f"{TESTING_DIR}/store/files/{files[i]}") for i in (0, 1)}
        self.assertEqual(the_set, {file_1_sum, file_2_sum})

    def test_load_and_retrieve_a_non_cached_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file")
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        self.assertEqual(len(files), 1)
        rmtree(f"{TESTING_DIR}/store/files")
        Path(f"{TESTING_DIR}/store/files").mkdir()
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 0)
        retrieve_file(f"{TESTING_DIR}/store", files[0])
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 1)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), file_1_sum)

    def test_load_and_retrieve_2_non_cached_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file")
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        self.assertEqual(len(files), 2)
        rmtree(f"{TESTING_DIR}/store/files")
        Path(f"{TESTING_DIR}/store/files").mkdir()
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 0)
        retrieve_file(f"{TESTING_DIR}/store", files[0])
        retrieve_file(f"{TESTING_DIR}/store", files[1])
        self.assertEqual(len(list(Path(f"{TESTING_DIR}/store/files").iterdir())), 2)
        the_set = {sha256sum(f"{TESTING_DIR}/store/files/{files[i]}") for i in (0, 1)}
        self.assertEqual(the_set, {file_1_sum, file_2_sum})

    def test_make_help(self):
        result = run(["make", "help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"make help failed: {result.stderr}")
        self.assertIn("Usage: make [target]", result.stdout)
        self.assertIn("Available targets:", result.stdout)
        self.assertIn("help", result.stdout)
        self.assertIn("Show this help message", result.stdout)
        self.assertIn("lint", result.stdout)
        self.assertIn("test", result.stdout)

    def test_store_without_rm_keeps_source(self):
        """Verify that without delete_source=True, the source file is kept"""
        source_file = Path(f"{TESTING_DIR}/source_file.txt")
        with source_file.open("w") as f:
            f.write("This file should remain after storage")
        self.assertTrue(source_file.exists())
        store_file(f"{TESTING_DIR}/store", str(source_file), delete_source=False)
        # Source file should still exist
        self.assertTrue(source_file.exists())
        with source_file.open() as f:
            self.assertEqual(f.read(), "This file should remain after storage")

    def test_store_with_rm_deletes_source(self):
        """Verify that with delete_source=True, the source file is deleted after successful storage"""
        source_file = Path(f"{TESTING_DIR}/source_file.txt")
        content = "This file should be deleted after storage"
        with source_file.open("w") as f:
            f.write(content)
        self.assertTrue(source_file.exists())
        store_file(f"{TESTING_DIR}/store", str(source_file), delete_source=True)
        # Source file should be gone
        self.assertFalse(source_file.exists())

    def test_store_with_rm_still_stores_correctly(self):
        """Verify that using delete_source=True doesn't affect the stored file integrity"""
        source_file = Path(f"{TESTING_DIR}/source_file.txt")
        content = "Content to be stored and source deleted"
        with source_file.open("w") as f:
            f.write(content)
        original_hash = sha256(content.encode("utf-8")).hexdigest()
        store_file(f"{TESTING_DIR}/store", str(source_file), delete_source=True)
        # Source should be deleted
        self.assertFalse(source_file.exists())
        # But file should be stored correctly
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        self.assertEqual(len(files), 1)
        stored_hash = sha256sum(f"{TESTING_DIR}/store/files/{files[0]}")
        self.assertEqual(stored_hash, original_hash)

    def test_store_with_rm_retrieves_correctly(self):
        """Verify that a file stored with delete_source=True can be retrieved correctly"""
        source_file = Path(f"{TESTING_DIR}/source_file.txt")
        content = "Content that should be retrievable even after source deletion"
        with source_file.open("w") as f:
            f.write(content)
        original_hash = sha256(content.encode("utf-8")).hexdigest()
        store_file(f"{TESTING_DIR}/store", str(source_file), delete_source=True)
        # Source should be deleted
        self.assertFalse(source_file.exists())
        # Get the UUID
        files = [p.name for p in Path(f"{TESTING_DIR}/store/files").iterdir()]
        uuid = files[0]
        # Delete cached file to force retrieval from encrypted version
        Path(f"{TESTING_DIR}/store/files/{uuid}").unlink()
        # Retrieve the file
        retrieve_file(f"{TESTING_DIR}/store", uuid)
        # Verify retrieved file matches original
        retrieved_hash = sha256sum(f"{TESTING_DIR}/store/files/{uuid}")
        self.assertEqual(retrieved_hash, original_hash)
        # Verify content
        with Path(f"{TESTING_DIR}/store/files/{uuid}").open() as f:
            self.assertEqual(f.read(), content)

    def test_store_with_rm_on_lock_error_keeps_source(self):
        """Verify that if storage fails (e.g., lock error), source file is NOT deleted"""
        source_file = Path(f"{TESTING_DIR}/source_file.txt")
        with source_file.open("w") as f:
            f.write("This file should remain if storage fails")
        # Acquire lock to force failure
        acquire_lock(f"{TESTING_DIR}/store")
        self.assertTrue(source_file.exists())
        with self.assertRaises(FVException):
            store_file(f"{TESTING_DIR}/store", str(source_file), delete_source=True)
        # Source file should still exist because storage failed
        self.assertTrue(source_file.exists())
        with source_file.open() as f:
            self.assertEqual(f.read(), "This file should remain if storage fails")

    def test_cli_without_rm_flag_keeps_source(self):
        """Test CLI: fv i file.txt (without --rm) should keep source file"""
        from json import dumps

        # Use absolute paths
        test_dir_abs = Path(TESTING_DIR).resolve()
        config_dir = test_dir_abs / ".config" / "fv"
        config_dir.mkdir(parents=True)
        store_path_abs = test_dir_abs / "store"
        config = {"stores": {"default": {"path": str(store_path_abs)}}}
        with (config_dir / "init.json").open("w") as f:
            f.write(dumps(config))

        # Create test file
        source_file = test_dir_abs / "test_cli.txt"
        with source_file.open("w") as f:
            f.write("CLI test without --rm")

        self.assertTrue(source_file.exists())

        # Run CLI without --rm flag
        import os
        import sys

        original_home = os.environ.get("HOME")
        original_gnupghome = os.environ.get("GNUPGHOME")
        original_pythonioencoding = os.environ.get("PYTHONIOENCODING")
        original_argv = sys.argv
        try:
            # Set GNUPGHOME to real user's gnupg dir so GPG agent works
            if original_home:
                os.environ["GNUPGHOME"] = str(Path(original_home) / ".gnupg")
            os.environ["HOME"] = str(test_dir_abs)
            os.environ["PYTHONIOENCODING"] = "utf-8"  # Ensure UTF-8 for Windows
            sys.argv = ["fv.py", "i", str(source_file)]

            # Import and run main
            from fv import main

            main()

            # Source file should still exist
            self.assertTrue(source_file.exists(), "Source file should NOT be deleted without --rm flag")
            with source_file.open() as f:
                self.assertEqual(f.read(), "CLI test without --rm")
        finally:
            if original_home:
                os.environ["HOME"] = original_home
            else:
                os.environ.pop("HOME", None)
            if original_gnupghome:
                os.environ["GNUPGHOME"] = original_gnupghome
            else:
                os.environ.pop("GNUPGHOME", None)
            if original_pythonioencoding:
                os.environ["PYTHONIOENCODING"] = original_pythonioencoding
            else:
                os.environ.pop("PYTHONIOENCODING", None)
            sys.argv = original_argv

    def test_cli_with_rm_flag_deletes_source(self):
        """Test CLI: fv i --rm file.txt should delete source file"""
        from json import dumps

        # Use absolute paths
        test_dir_abs = Path(TESTING_DIR).resolve()
        config_dir = test_dir_abs / ".config" / "fv"
        config_dir.mkdir(parents=True)
        store_path_abs = test_dir_abs / "store"
        config = {"stores": {"default": {"path": str(store_path_abs)}}}
        with (config_dir / "init.json").open("w") as f:
            f.write(dumps(config))

        # Create test file
        source_file = test_dir_abs / "test_cli_rm.txt"
        with source_file.open("w") as f:
            f.write("CLI test with --rm")

        self.assertTrue(source_file.exists())

        # Run CLI with --rm flag
        import os
        import sys

        original_home = os.environ.get("HOME")
        original_gnupghome = os.environ.get("GNUPGHOME")
        original_pythonioencoding = os.environ.get("PYTHONIOENCODING")
        original_argv = sys.argv
        try:
            # Set GNUPGHOME to real user's gnupg dir so GPG agent works
            if original_home:
                os.environ["GNUPGHOME"] = str(Path(original_home) / ".gnupg")
            os.environ["HOME"] = str(test_dir_abs)
            os.environ["PYTHONIOENCODING"] = "utf-8"  # Ensure UTF-8 for Windows
            sys.argv = ["fv.py", "i", "--rm", str(source_file)]

            # Import and run main
            from fv import main

            main()

            # Source file should be deleted
            self.assertFalse(source_file.exists(), "Source file should be deleted with --rm flag")
        finally:
            if original_home:
                os.environ["HOME"] = original_home
            else:
                os.environ.pop("HOME", None)
            if original_gnupghome:
                os.environ["GNUPGHOME"] = original_gnupghome
            else:
                os.environ.pop("GNUPGHOME", None)
            if original_pythonioencoding:
                os.environ["PYTHONIOENCODING"] = original_pythonioencoding
            else:
                os.environ.pop("PYTHONIOENCODING", None)
            sys.argv = original_argv

    def test_cli_autodetect_without_rm_keeps_source(self):
        """Test CLI: fv file.txt (autodetect mode without --rm) should keep source file"""
        from json import dumps

        # Use absolute paths
        test_dir_abs = Path(TESTING_DIR).resolve()
        config_dir = test_dir_abs / ".config" / "fv"
        config_dir.mkdir(parents=True)
        store_path_abs = test_dir_abs / "store"
        config = {"stores": {"default": {"path": str(store_path_abs)}}}
        with (config_dir / "init.json").open("w") as f:
            f.write(dumps(config))

        # Create test file
        source_file = test_dir_abs / "test_autodetect.txt"
        with source_file.open("w") as f:
            f.write("Autodetect test without --rm")

        self.assertTrue(source_file.exists())

        # Run CLI in autodetect mode without --rm
        import os
        import sys

        original_home = os.environ.get("HOME")
        original_gnupghome = os.environ.get("GNUPGHOME")
        original_pythonioencoding = os.environ.get("PYTHONIOENCODING")
        original_argv = sys.argv
        try:
            # Set GNUPGHOME to real user's gnupg dir so GPG agent works
            if original_home:
                os.environ["GNUPGHOME"] = str(Path(original_home) / ".gnupg")
            os.environ["HOME"] = str(test_dir_abs)
            os.environ["PYTHONIOENCODING"] = "utf-8"  # Ensure UTF-8 for Windows
            sys.argv = ["fv.py", str(source_file)]

            # Import and run main
            from fv import main

            main()

            # Source file should still exist
            self.assertTrue(source_file.exists(), "Source file should NOT be deleted without --rm flag")
            with source_file.open() as f:
                self.assertEqual(f.read(), "Autodetect test without --rm")
        finally:
            if original_home:
                os.environ["HOME"] = original_home
            else:
                os.environ.pop("HOME", None)
            if original_gnupghome:
                os.environ["GNUPGHOME"] = original_gnupghome
            else:
                os.environ.pop("GNUPGHOME", None)
            if original_pythonioencoding:
                os.environ["PYTHONIOENCODING"] = original_pythonioencoding
            else:
                os.environ.pop("PYTHONIOENCODING", None)
            sys.argv = original_argv


if __name__ == "__main__":
    unittest_main()
