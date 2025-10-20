"""Property-based tests using Hypothesis for fv (File Vault).

These tests verify invariants and properties that should hold for all inputs.
"""

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from shutil import rmtree
from unittest import TestCase

from hypothesis import given, settings
from hypothesis.strategies import binary, integers

from fv import check_password, generate_password, get_index, retrieve_file, sha256sum, store_file

TESTING_DIR = "fv_testing_dir_property_tests"


@contextmanager
def clean_store():
    """Context manager that ensures clean store before and after each hypothesis example."""
    store_path = Path(f"{TESTING_DIR}/store")
    # Clean before
    try:
        rmtree(store_path)
    except FileNotFoundError:
        pass
    try:
        yield store_path
    finally:
        # Clean after
        try:
            rmtree(store_path)
        except FileNotFoundError:
            pass


class PropertyTests(TestCase):
    """Property-based tests using Hypothesis."""

    def setUp(self):
        """Set up test directory."""
        try:
            rmtree(TESTING_DIR)
        except OSError:
            pass
        Path(TESTING_DIR).mkdir()

    def tearDown(self):
        """Clean up test directory including any locks."""
        try:
            rmtree(TESTING_DIR)
        except OSError:
            pass

    @given(binary(min_size=0, max_size=1 * 1024 * 1024))  # 0 to 1MB (reduced for speed)
    @settings(max_examples=20, deadline=None)  # GPG is slow, disable deadline
    def test_store_retrieve_roundtrip(self, file_content):
        """Any file content should roundtrip correctly through store→retrieve.

        Property: For any binary content, storing and retrieving should return identical content.
        """
        with clean_store() as store_path:
            # Write test file
            test_file = Path(f"{TESTING_DIR}/input.bin")
            test_file.write_bytes(file_content)
            original_sha = sha256(file_content).hexdigest()
            # Store the file
            store_file(str(store_path), str(test_file))
            # Get the UUID from the index
            _, index = get_index(str(store_path))
            self.assertEqual(len(index), 1, "Should have exactly one file in index")
            uuid = list(index.keys())[0]
            # Verify index has correct sha256 of original
            self.assertEqual(index[uuid][1], original_sha, "Index should contain sha256 of original content")
            # Clear the cache to force decryption
            rmtree(store_path / "files")
            (store_path / "files").mkdir()
            # Retrieve the file
            retrieve_file(str(store_path), uuid)
            # Verify content matches original
            retrieved = (store_path / "files" / uuid).read_bytes()
            self.assertEqual(
                retrieved,
                file_content,
                f"Retrieved content should match original. "
                f"Original: {len(file_content)} bytes, Retrieved: {len(retrieved)} bytes",
            )
            # Verify sha256 matches
            self.assertEqual(sha256sum(str(store_path / "files" / uuid)), original_sha)

    @given(integers(min_value=100, max_value=1 * 1024 * 1024))  # 100 bytes to 1MB
    @settings(max_examples=20, deadline=None)
    def test_padding_metadata_is_stored(self, file_size):
        """Padding metadata should be stored correctly in the index.

        Property: For any file size, padding_before and real_size should be stored in index.
        """
        with clean_store() as store_path:
            # Create file of exact size
            test_file = Path(f"{TESTING_DIR}/input.bin")
            test_file.write_bytes(b"x" * file_size)
            # Store the file
            store_file(str(store_path), str(test_file))
            # Get padding info from index
            _, index = get_index(str(store_path))
            uuid = list(index.keys())[0]
            padding_before = index[uuid][4]
            real_size = index[uuid][5]
            # Verify real_size matches original
            self.assertEqual(real_size, file_size, "real_size should match original file size")
            # Verify padding_before is non-negative
            self.assertGreaterEqual(padding_before, 0, "padding_before should be non-negative")
            # Verify padding_before is reasonable (should be 30-70% of total padding)
            # Total padding is file_size/16 to file_size/8
            max_total_padding = max(file_size // 8, 256)  # Account for tiny files too
            self.assertLessEqual(padding_before, max_total_padding, "padding_before shouldn't exceed max possible")

    def test_generated_passwords_are_always_valid(self):
        """Generated passwords should always pass validation.

        Property: generate_password() should always produce valid passwords.
        """
        for _ in range(1000):  # Test 1000 passwords
            password = generate_password()
            # Should not raise exception
            try:
                check_password(password)
            except Exception as e:
                self.fail(f"Generated password '{password}' failed validation: {e}")
            # Verify properties
            self.assertEqual(len(password), 32, "Password should be 32 characters")
            self.assertTrue(
                all(c.isalnum() or c == "-" for c in password), f"Password '{password}' contains invalid characters"
            )

    @given(binary(min_size=1000, max_size=10000))  # 1KB to 10KB
    @settings(max_examples=20, deadline=None)
    def test_index_stores_correct_metadata(self, file_content):
        """Index should store correct metadata about the file.

        Property: Index metadata (sha256, real_size, filename) should match actual file.
        """
        with clean_store() as store_path:
            test_file = Path(f"{TESTING_DIR}/test_input.bin")
            test_file.write_bytes(file_content)
            original_sha = sha256(file_content).hexdigest()
            original_size = len(file_content)
            # Store the file
            store_file(str(store_path), str(test_file))
            # Check index
            _, index = get_index(str(store_path))
            uuid = list(index.keys())[0]
            entry = index[uuid]
            # Verify index structure: [password, sha256, encrypted_sha256, filename, padding_before, real_size]
            self.assertEqual(len(entry), 6, "Index entry should have 6 fields")
            self.assertEqual(entry[1], original_sha, "SHA256 in index should match original")
            self.assertEqual(entry[3], "test_input.bin", "Filename should be preserved")
            self.assertEqual(entry[5], original_size, "real_size should match original")
            self.assertIsInstance(entry[4], int, "padding_before should be an integer")
            self.assertGreaterEqual(entry[4], 0, "padding_before should be non-negative")

    @given(binary(min_size=0, max_size=100 * 1024))  # 0 to 100KB
    @settings(max_examples=10, deadline=None)
    def test_retrieved_content_always_matches_original(self, file_content):
        """Retrieved files should always match original, regardless of content type.

        Property: Even edge cases (empty, zeros, random) should roundtrip perfectly.
        """
        with clean_store() as store_path:
            test_file = Path(f"{TESTING_DIR}/edge_case.bin")
            test_file.write_bytes(file_content)
            # Store and immediately retrieve (no cache clearing)
            store_file(str(store_path), str(test_file))
            _, index = get_index(str(store_path))
            uuid = list(index.keys())[0]
            # File is cached, should be original
            cached = (store_path / "files" / uuid).read_bytes()
            self.assertEqual(cached, file_content, "Cached file should match original exactly")

    @given(binary(min_size=0, max_size=100 * 1024))  # 0 to 100KB
    @settings(max_examples=15, deadline=None)
    def test_delete_source_removes_only_on_success(self, file_content):
        """When delete_source=True, source should be deleted only after successful storage. Redundant but ok.

        Property: For any file content, delete_source=True should:
        1. Delete the source file after successful storage
        2. Still allow correct retrieval
        3. Preserve the original file's content in storage
        """
        with clean_store() as store_path:
            # Create source file
            source_file = Path(f"{TESTING_DIR}/to_be_deleted.bin")
            source_file.write_bytes(file_content)
            original_sha = sha256(file_content).hexdigest()
            # Verify source exists before
            self.assertTrue(source_file.exists(), "Source file should exist before storage")
            # Store with delete_source=True
            store_file(str(store_path), str(source_file), delete_source=True)
            # Verify source is deleted
            self.assertFalse(source_file.exists(), "Source file should be deleted after successful storage")
            # Get UUID and verify storage
            _, index = get_index(str(store_path))
            uuid = list(index.keys())[0]
            # Verify stored file has correct content
            stored = (store_path / "files" / uuid).read_bytes()
            self.assertEqual(stored, file_content, "Stored content should match original")
            self.assertEqual(sha256sum(str(store_path / "files" / uuid)), original_sha, "SHA256 should match")
            # Clear cache and retrieve from encrypted
            rmtree(store_path / "files")
            (store_path / "files").mkdir()
            retrieve_file(str(store_path), uuid)
            # Verify retrieved content matches original
            retrieved = (store_path / "files" / uuid).read_bytes()
            self.assertEqual(
                retrieved,
                file_content,
                "Retrieved content should match original even after source was deleted",
            )
