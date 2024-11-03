"""
fv - File Vault
MIT License - Copyright (c) 2024 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
- If you want a production-ready e2e cloud with many features, check https://github.com/Scille/parsec-cloud
  - Ngl they should rename it tho
TODOs and possible improvements:
- capture stdin, stderr, stdout for encrypt and decrypt
- make metadata a tree, split letter by letter for the X firsts, then a final dir for the rest, then use existing logic
"""
# TODO : pyproject + ruff, even tho useless for now


from subprocess import Popen, PIPE
from pathlib import Path
from json import loads, dumps
from os import listdir, remove
from uuid import uuid4
from shutil import copy as copy_file, rmtree
from hashlib import sha256 as sha256_hasher

 
def sha256sum(file_path):
    with open(file_path, "rb") as f:
        sha256_hash = sha256_hasher()
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
        return sha256_hash.hexdigest()


def check_password(password):
    if type(password) != str:
        raise Exception("Password must be a string")
    if any(not ("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c == "-") for c in password):
        raise Exception("Password must be a [[ [A-Z] [a-z] [0-9] \\- ]] string")


def encrypt_file(filepath, password):
    check_password(password)
    p = Popen(["gpg", "--pinentry-mode", "loopback", "--passphrase", password, "-c", filepath])
    p.wait()


def decrypt_file(filepath, password):
    check_password(password)
    if filepath[-4:] != ".gpg" or len(filepath) < 4:
        raise Exception("filepath must end with .gpg")
    p = Popen(
        ["gpg", "--batch", "--yes", "--passphrase-fd", "0", "--output", filepath[:-4], "--decrypt", filepath],
        stdin=PIPE,
    )
    p.communicate(bytes(password, encoding="ascii"))
    p.wait()


def get_index(store_path):
    """Returns current_index_version, current_index"""
    saved_indexes = listdir(Path(f"{store_path}/index"))
    if len(saved_indexes) == 0:
        return 0, {}
    if any(not s.endswith(".json") or len(s) != 21 for s in saved_indexes):
        print(saved_indexes)
        raise Exception("Wrong index name detected")  # Maybe overkill but keeping this for now
    current_index_file_name = max(saved_indexes)
    with open(f"{store_path}/index/{current_index_file_name}", "r") as f:
        current_index = loads(f.read())
    return int(current_index_file_name[:16], 16), current_index


def update_index(store_path, next_index_version, next_index):
    with open(f"{store_path}/index/{hex(next_index_version)[2:].zfill(16)}.json", "w") as f:
        f.write(dumps(next_index))


def acquire_lock(store_path):
    for file_name in ["index", "files", "encrypted_files", "wip"]:
        Path(f"{store_path}/{file_name}").mkdir(parents=True, exist_ok=True)
    try:
        with open(f"{store_path}/.lock", "x") as f:
            pass
    except FileExistsError:
        raise Exception(
            f"Failed to acquire lock. "
            f"If no instance of the tool is running, you may remove the {store_path}/.lock"
        )


def release_lock(store_path):
    rmtree(f"{store_path}/wip")
    remove(f"{store_path}/.lock")


def locked(func):
    def wrapper(store_path, *args, **kwargs):
        acquire_lock(store_path)
        try:
            func(store_path, *args, **kwargs)
        except Exception as exc:
            release_lock(store_path)
            raise exc
        release_lock(store_path)
    return wrapper


@locked
def store_file(store_path, file_path, password):
    index_version, index = get_index(store_path)
    u = str(uuid4())
    if u in index:
        raise Exception("Time to play the lottery I guess")
    file_name = Path(file_path).parts[-1]  # Assumes Windows path on Windows and Unix path on Unix
    copy_file(file_path, f"{store_path}/wip/{u}")
    encrypt_file(f"{store_path}/wip/{u}", password)
    copy_file(f"{store_path}/wip/{u}.gpg", f"{store_path}/encrypted_files/{u}.gpg")
    copy_file(f"{store_path}/wip/{u}", f"{store_path}/files/{u}")
    regular_file_sha256 = sha256sum(f"{store_path}/wip/{u}")
    encrypted_file_sha256 = sha256sum(f"{store_path}/wip/{u}.gpg")
    index[u] = [regular_file_sha256, encrypted_file_sha256, file_name]
    update_index(store_path, index_version + 1, index)


@locked
def retrieve_file(store_path, uuid, password):
    if Path(f"{store_path}/files/{uuid}").is_file():
        return
    copy_file(f"{store_path}/encrypted_files/{uuid}.gpg", f"{store_path}/wip/{uuid}.gpg")
    decrypt_file(f"{store_path}/wip/{uuid}.gpg", password)
    copy_file(f"{store_path}/wip/{uuid}", f"{store_path}/files/{uuid}")


# fv i file - TODO
#  - will store the filename as metadata - TODO
# fv o uuid [path] - if no path just put in unencrpyted - TODO

# 4 dirs :
# - files
# - encrypted_files
# - index
# - wip
