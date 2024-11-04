#!/usr/bin/env python

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

from hashlib import sha256 as sha256_hasher
from json import dumps, loads
from os import listdir
from pathlib import Path
from secrets import choice
from shutil import copy as copy_file
from shutil import rmtree
from string import ascii_letters, digits
from subprocess import PIPE, Popen
from sys import argv
from uuid import UUID, uuid4


class FVException(Exception):
    pass


def sha256sum(file_path):
    with Path(file_path).open("rb") as f:
        sha256_hash = sha256_hasher()
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
        return sha256_hash.hexdigest()


def generate_password():  # I should make something better
    return "".join(choice(ascii_letters + digits) for i in range(32))  # TODO : Better actually, ngl


def check_password(password):
    if type(password) is not str:
        raise FVException("Password must be a string")
    if any(not ("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c == "-") for c in password):
        raise FVException("Password must be a [[ [A-Z] [a-z] [0-9] \\- ]] string")


def encrypt_file(filepath, password):
    check_password(password)
    p = Popen(["gpg", "--pinentry-mode", "loopback", "--passphrase", password, "-c", filepath])
    p.wait()


def decrypt_file(filepath, password):
    check_password(password)
    if filepath[-4:] != ".gpg" or len(filepath) < 4:
        raise FVException("filepath must end with .gpg")
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
        raise FVException("Wrong index name detected")  # Maybe overkill but keeping this for now
    current_index_file_name = max(saved_indexes)
    with Path(f"{store_path}/index/{current_index_file_name}").open() as f:
        current_index = loads(f.read())
    return int(current_index_file_name[:16], 16), current_index


def update_index(store_path, next_index_version, next_index):
    with Path(f"{store_path}/index/{hex(next_index_version)[2:].zfill(16)}.json").open("w") as f:
        f.write(dumps(next_index))


def acquire_lock(store_path):
    for file_name in ["index", "files", "encrypted_files", "wip"]:
        Path(f"{store_path}/{file_name}").mkdir(parents=True, exist_ok=True)
    try:
        with Path(f"{store_path}/.lock").open("x"):
            pass
    except FileExistsError:
        raise FVException(
            f"Failed to acquire lock.\nIf no instance of the tool is running, you may remove the {store_path}/.lock"
        ) from None


def release_lock(store_path):
    rmtree(f"{store_path}/wip")
    Path(f"{store_path}/.lock").unlink()


def locked(func):
    def wrapper(store_path, *args, **kwargs):
        acquire_lock(store_path)
        try:
            func(store_path, *args, **kwargs)
        except FVException as exc:
            release_lock(store_path)
            raise exc
        release_lock(store_path)

    return wrapper


@locked
def store_file(store_path, file_path):
    index_version, index = get_index(store_path)
    u = str(uuid4())
    password = generate_password()
    if u in index:
        raise FVException("Time to play the lottery I guess")
    file_name = Path(file_path).parts[-1]  # Assumes Windows path on Windows and Unix path on Unix
    copy_file(file_path, f"{store_path}/wip/{u}")
    encrypt_file(f"{store_path}/wip/{u}", password)
    copy_file(f"{store_path}/wip/{u}.gpg", f"{store_path}/encrypted_files/{u}.gpg")
    copy_file(f"{store_path}/wip/{u}", f"{store_path}/files/{u}")
    regular_file_sha256 = sha256sum(f"{store_path}/wip/{u}")
    encrypted_file_sha256 = sha256sum(f"{store_path}/wip/{u}.gpg")
    index[u] = [password, regular_file_sha256, encrypted_file_sha256, file_name]
    update_index(store_path, index_version + 1, index)
    print(u)


@locked
def retrieve_file(store_path, uuid):
    if Path(f"{store_path}/files/{uuid}").is_file():
        return
    _, index = get_index(store_path)
    password = index[uuid][0]
    copy_file(f"{store_path}/encrypted_files/{uuid}.gpg", f"{store_path}/wip/{uuid}.gpg")
    decrypt_file(f"{store_path}/wip/{uuid}.gpg", password)
    copy_file(f"{store_path}/wip/{uuid}", f"{store_path}/files/{uuid}")


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    conf = """~/.config/fv/init.json => {"stores": {"default": {"path": "path-that-will-include-the-subdirs"}}}"""
    output_lines = [
        "fv - File Vault",
        "===============",
        conf,
        "  - creates 4 subdirs :\n    - files\n    - encrypted_files\n    - index\n    - wip",
        "===============",
        "- fv i file_path         ==> encrypt with a single-use password, index, and store a file in /encrypted_files",
        "- fv o uuid              ==> recover an indexed file from /encrypted_files to /file using the uuid from i",
        "- fv [[path] OR [uuid]]  ==> retrieves if the argument is an uuid, else stores as path",
        "===============",
        "You can store any file and record it's uuid in your knowledge base or any other external tool",
        "You can version /indexes and securely share it between your local devices",
        "You can remote sync /encrypted_files to many remote unsecure servers as those are encrypted and hashed",
    ]
    red_indexes = ([2] if wrong_config else []) + ([5, 6, 7] if wrong_command or wrong_arg_len else [])
    output_lines = [f"\033[93m{line}\033[0m" if i in red_indexes else line for i, line in enumerate(output_lines)]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def main():
    try:
        with (Path.home() / ".config" / "fv" / "init.json").open() as f:
            config = loads(f.read())
        store_path = config["stores"]["default"]["path"]
    except Exception:
        return usage(wrong_config=True)
    if len(argv) == 2:  # Try guess
        try:
            u, file_path = UUID(argv[1]), None
        except ValueError:
            u, file_path = None, argv[1]
        if u is not None:
            retrieve_file(store_path, str(u))
        else:
            store_file(store_path, file_path)
    elif len(argv) == 3:
        if argv[1] == "o":
            retrieve_file(store_path, str(UUID(argv[2])))
        elif argv[1] == "i":
            store_file(store_path, argv[2])
        else:
            return usage(wrong_command=True)
    else:
        return usage(wrong_arg_len=True)


if __name__ == "__main__":
    main()
