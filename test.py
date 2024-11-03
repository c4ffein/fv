from os import mkdir, rmdir, remove, listdir
from shutil import rmtree
from unittest import TestCase, main as unittest_main, mock
from json import loads, dumps
from pathlib import Path
from hashlib import sha256

from fv import sha256sum, encrypt_file, decrypt_file, get_index, acquire_lock, release_lock, store_file, retrieve_file

TESTING_DIR = "fv_testing_dir_947f6128-4d75-40bb-a9ad-1a64342bd860"
STORE_DIR = f"{TESTING_DIR}/store_dir"  # TODO?


class FVTest(TestCase):
    def _clean_test_dir(self):
        try:
            rmtree(TESTING_DIR)
        except OSError:
            pass

    def setUp(self):
        self._clean_test_dir()
        mkdir(TESTING_DIR)

    def tearDown(self):
        self._clean_test_dir()

    def test_sha256(self):
        with open(f"{TESTING_DIR}/test_mdr1.txt", "w") as f:
            f.write("I am a goofy file")
        self.assertEqual(
            sha256sum(f"{TESTING_DIR}/test_mdr1.txt"),
            "076dd4d0add0c2ce14af7579551fea579f7671ee1668421c12f080b5f25af1d2"
        )

    def test_encrypt_decrypt(self):
        """Quick and dirty because re-encrypting doesn't guarantee the same output, just encrypt and decrypt again"""
        with open(f"{TESTING_DIR}/test_mdr1.txt", "w") as f:
            f.write("I am a goofy file")
        encrypt_file(f"{TESTING_DIR}/test_mdr1.txt", "stoopid-Password-0")
        remove(f"{TESTING_DIR}/test_mdr1.txt")
        decrypt_file(f"{TESTING_DIR}/test_mdr1.txt.gpg", "stoopid-Password-0")
        with open(f"{TESTING_DIR}/test_mdr1.txt", "r") as f:
            o = f.read()
        assert o == "I am a goofy file"

    def test_try_encrypt_unacceptable_password(self):
        with open(f"{TESTING_DIR}/test_mdr1.txt", "w") as f:
            f.write("I am a goofy file")
        with self.assertRaises(Exception):
            encrypt_file(f"{TESTING_DIR}/test_mdr1.txt", "stoopid-password-\"")

    def test_can_get_hex_index(self):
        mkdir(f"{TESTING_DIR}/index")
        with open(f"{TESTING_DIR}/index/00a200030004000a.json", "w") as f:
            f.write(dumps({"I am": "an index"}))
        self.assertEqual(get_index(f"{TESTING_DIR}"), (45598959112290314, {"I am": "an index"}))

    def test_cant_double_aquire(self):
        acquire_lock(TESTING_DIR)
        with self.assertRaises(Exception):
            acquire_lock(TESTING_DIR)

    def test_can_acquire_release_acquire_release(self):
        acquire_lock(TESTING_DIR)
        release_lock(TESTING_DIR)
        acquire_lock(TESTING_DIR)
        release_lock(TESTING_DIR)

    def test_cant_store_while_locked(self):
        acquire_lock(f"{TESTING_DIR}/store")
        with self.assertRaises(Exception):
            store_file(f"{TESTING_DIR}/store", f"{TESTING_DIR}/file.txt", "pass")
    
    def test_cant_retrieve_while_locked(self):
        acquire_lock(f"{TESTING_DIR}/store")
        with self.assertRaises(Exception):
            retrieve_file(f"{TESTING_DIR}/store", "42", "pass")
    
    def _load_a_file(self, file_name, file_content, password):
        with open(f"{TESTING_DIR}/{file_name}", "w") as f:
            f.write(file_content)
        store_file(f"{TESTING_DIR}/store", f"{TESTING_DIR}/{file_name}", password)
        return sha256(file_content.encode("utf-8")).hexdigest()

    def test_load_1_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file", "pass")
        with open(f"{TESTING_DIR}/store/index/0000000000000001.json", "r") as f:
            index = loads(f.read())
        self.assertEqual(type(index), dict)
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 3)])
        self.assertEqual(next(iter(index.items())), (mock.ANY, [file_1_sum, mock.ANY, "file.txt"]))
        index_1 = [*index.keys()][0]
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_1}"), file_1_sum)
        assert all(s.endswith(".gpg") for s in listdir(Path(f"{TESTING_DIR}/store/encrypted_files")))
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_1}.gpg", "pass")
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_1}"), file_1_sum)

    def test_load_2_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file", "pass")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file", "pass")
        with open(f"{TESTING_DIR}/store/index/0000000000000002.json", "r") as f:
            index = loads(f.read())
        self.assertEqual(type(index), dict)
        self.assertEqual(len(index), 2)
        self.assertEqual([(len(k), len(v)) for k, v in index.items()], [(36, 3), (36, 3)])
        values = [v for v in index.values()]
        self.assertEqual((values[0][0], values[0][2]), (file_1_sum, "file_1.txt"))
        self.assertEqual((values[1][0], values[1][2]), (file_2_sum, "file_2.txt"))
        index_1, index_2 = index.keys()
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_1}"), file_1_sum)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{index_2}"), file_2_sum)
        assert all(s.endswith(".gpg") for s in listdir(Path(f"{TESTING_DIR}/store/encrypted_files")))
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_1}.gpg", "pass")
        decrypt_file(f"{TESTING_DIR}/store/encrypted_files/{index_2}.gpg", "pass")
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_1}"), file_1_sum)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/encrypted_files/{index_2}"), file_2_sum)

    def test_load_and_retrieve_a_cached_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file", "pass")
        files = listdir(Path(f"{TESTING_DIR}/store/files"))
        self.assertEqual(len(files), 1)
        retrieve_file(f"{TESTING_DIR}/store", files[0], "pass")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 1)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), file_1_sum)

    def test_load_and_retrieve_2_cached_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file", "pass")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file", "pass")
        files = listdir(Path(f"{TESTING_DIR}/store/files"))
        self.assertEqual(len(files), 2)
        retrieve_file(f"{TESTING_DIR}/store", files[0], "pass")
        retrieve_file(f"{TESTING_DIR}/store", files[1], "pass")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 2)
        the_set = {
            sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), sha256sum(f"{TESTING_DIR}/store/files/{files[1]}")
        }
        self.assertEqual(the_set, {file_1_sum, file_2_sum})
    
    def test_load_and_retrieve_a_non_cached_file(self):
        file_1_sum = self._load_a_file("file.txt", "I am a goofy file", "pass")
        files = listdir(Path(f"{TESTING_DIR}/store/files"))
        self.assertEqual(len(files), 1)
        rmtree(f"{TESTING_DIR}/store/files")
        mkdir(f"{TESTING_DIR}/store/files")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 0)
        retrieve_file(f"{TESTING_DIR}/store", files[0], "pass")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 1)
        self.assertEqual(sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), file_1_sum)

    def test_load_and_retrieve_2_non_cached_files(self):
        file_1_sum = self._load_a_file("file_1.txt", "I am a first goofy file", "pass")
        file_2_sum = self._load_a_file("file_2.txt", "I am a second goofy file", "pass")
        files = listdir(Path(f"{TESTING_DIR}/store/files"))
        self.assertEqual(len(files), 2)
        rmtree(f"{TESTING_DIR}/store/files")
        mkdir(f"{TESTING_DIR}/store/files")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 0)
        retrieve_file(f"{TESTING_DIR}/store", files[0], "pass")
        retrieve_file(f"{TESTING_DIR}/store", files[1], "pass")
        self.assertEqual(len(listdir(Path(f"{TESTING_DIR}/store/files"))), 2)
        the_set = {
            sha256sum(f"{TESTING_DIR}/store/files/{files[0]}"), sha256sum(f"{TESTING_DIR}/store/files/{files[1]}")
        }
        self.assertEqual(the_set, {file_1_sum, file_2_sum})


if __name__ == "__main__":
    unittest_main()
