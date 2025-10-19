from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from shutil import rmtree
from unittest import TestCase, mock
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
        acquire_lock(f"{TESTING_DIR}/store")
        with self.assertRaises(FVException):
            store_file(f"{TESTING_DIR}/store", f"{TESTING_DIR}/file.txt", "pass")

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
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 4)])
        self.assertEqual(next(iter(index.items())), (mock.ANY, [mock.ANY, file_1_sum, mock.ANY, "file.txt"]))
        index_1 = [*index.keys()][0]
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_1}"), file_1_sum)
        assert all(p.name.endswith(".gpg") for p in Path(f"{TESTING_DIR}/store/encrypted_files").iterdir())
        password = next(iter(index.values()))[0]
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_1}.gpg", password)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_1}"), file_1_sum)

    def test_load_2_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file")
        with Path(f"{TESTING_DIR}/store/index/0000000000000002.json").open() as f:
            index = loads(f.read())
        self.assertEqual(type(index), dict)
        self.assertEqual(len(index), 2)
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 4), (36, 4)])
        values = list(index.values())
        self.assertEqual((values[0][1], values[0][3]), (file_1_sum, "file_1.txt"))
        self.assertEqual((values[1][1], values[1][3]), (file_2_sum, "file_2.txt"))
        index_1, index_2 = index.keys()
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_1}"), file_1_sum)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_2}"), file_2_sum)
        assert all(p.name.endswith(".gpg") for p in Path(f"{TESTING_DIR}/store/encrypted_files").iterdir())
        password_1, password_2 = (v[0] for v in index.values())
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_1}.gpg", password_1)
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_2}.gpg", password_2)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_1}"), file_1_sum)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_2}"), file_2_sum)

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


if __name__ == "__main__":
    unittest_main()
