#!/usr/bin/env python

"""
fv - File Vault
MIT License - Copyright (c) 2024 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
- If you want a production-ready e2e cloud with many features, check https://github.com/Scille/parsec-cloud
  - Ngl they should rename it tho
TODOs and possible improvements:
- make metadata a tree, split letter by letter for the X firsts, then a final dir for the rest, then use existing logic
- add some random length random padding to files before encrypt, just also store actual length in index
- maybe even add some random length padding before, and also include length of initial padding in index
- option in the index to make fv automatically rm source on import, or even if and only if the i arg is used
"""

from hashlib import sha256 as sha256_hasher
from json import dumps, loads
from os import name as os_name
from pathlib import Path
from secrets import choice
from shutil import copy as copy_file
from shutil import rmtree
from string import ascii_letters, digits
from subprocess import PIPE, Popen
from sys import argv
from uuid import UUID, uuid4
from warnings import warn


class FVException(Exception):
    pass


def sha256sum(file_path):
    with Path(file_path).open("rb") as f:
        sha256_hash = sha256_hasher()
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
        return sha256_hash.hexdigest()


def generate_password():  # Could use token_urlsafe, keeping as-is for now
    return "".join(choice(ascii_letters + digits) for i in range(32))


def check_password(password):
    if type(password) is not str:
        raise FVException("Password must be a string")
    if any(not ("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c == "-") for c in password):
        raise FVException("Password must be a [[ [A-Z] [a-z] [0-9] \\- ]] string")


def encrypt_file(filepath, password):
    check_password(password)
    filepath = str(Path(filepath))  # Ensure string for subprocess
    p = Popen(
        ["gpg", "--batch", "--yes", "--passphrase-fd", "0", "--symmetric", filepath],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    stdout, stderr = p.communicate(bytes(password, encoding="ascii"))
    if p.returncode != 0:
        raise FVException(f"GPG encryption failed: {stderr.decode('utf-8', errors='replace')}")


def decrypt_file(filepath, password):
    check_password(password)
    filepath = Path(filepath)
    if filepath.suffix != ".gpg":
        raise FVException("filepath must end with .gpg")
    output_path = filepath.with_suffix("")  # Remove .gpg extension
    p = Popen(
        ["gpg", "--batch", "--yes", "--passphrase-fd", "0", "--output", str(output_path), "--decrypt", str(filepath)],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    stdout, stderr = p.communicate(bytes(password, encoding="ascii"))
    if p.returncode != 0:
        raise FVException(f"GPG decryption failed: {stderr.decode('utf-8', errors='replace')}")


def get_index(store_path):
    """Returns current_index_version, current_index"""
    store_path = Path(store_path)
    saved_indexes = [p.name for p in (store_path / "index").iterdir()]
    if len(saved_indexes) == 0:
        return 0, {}
    if any(not s.endswith(".json") or len(s) != 21 for s in saved_indexes):
        print(saved_indexes)
        raise FVException("Wrong index name detected")  # Maybe overkill but keeping this for now
    current_index_file_name = max(saved_indexes)
    with (store_path / "index" / current_index_file_name).open() as f:
        current_index = loads(f.read())
    return int(current_index_file_name[:16], 16), current_index


def update_index(store_path, next_index_version, next_index):
    store_path = Path(store_path)
    with (store_path / "index" / f"{next_index_version:016x}.json").open("w") as f:
        f.write(dumps(next_index))


def acquire_lock(store_path):
    store_path = Path(store_path)
    if os_name == "nt":  # Windows warning
        warn(
            "Windows does not support Unix-style file permissions (chmod/mode). "
            "Directories are created with default Windows permissions, and aren't changed for existing ones. "
            "Please ensure appropriate access controls are set using Windows ACLs "
            "to restrict access to your user only.",
            UserWarning,
            stacklevel=2,
        )
    for file_name in ["index", "files", "encrypted_files", "wip"]:
        subdir = store_path / file_name
        if os_name != "nt":  # Unix-like systems
            subdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:  # Windows
            subdir.mkdir(parents=True, exist_ok=True)
    if os_name != "nt":  # Unix-like systems only
        store_path.chmod(0o700)  # Warning : chmod doesn't set rights of parents
    try:
        with (store_path / ".lock").open("x"):
            pass
    except FileExistsError:
        raise FVException(
            f"Failed to acquire lock.\nIf no instance of the tool is running, you may remove the {store_path / '.lock'}"
        ) from None


def release_lock(store_path):
    store_path = Path(store_path)
    rmtree(store_path / "wip")
    (store_path / ".lock").unlink()


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
    store_path = Path(store_path)
    index_version, index = get_index(store_path)
    u = str(uuid4())
    password = generate_password()
    if u in index:
        raise FVException("Time to play the lottery I guess")
    file_name = Path(file_path).name  # Works cross-platform
    wip_file = store_path / "wip" / u
    wip_file_gpg = store_path / "wip" / f"{u}.gpg"
    encrypted_file = store_path / "encrypted_files" / f"{u}.gpg"
    stored_file = store_path / "files" / u
    copy_file(file_path, wip_file)
    encrypt_file(wip_file, password)
    copy_file(wip_file_gpg, encrypted_file)
    copy_file(wip_file, stored_file)
    regular_file_sha256 = sha256sum(wip_file)
    encrypted_file_sha256 = sha256sum(wip_file_gpg)
    index[u] = [password, regular_file_sha256, encrypted_file_sha256, file_name]
    update_index(store_path, index_version + 1, index)
    print(u)


@locked
def retrieve_file(store_path, uuid):
    store_path = Path(store_path)
    _, index = get_index(store_path)
    print(index[uuid][1], index[uuid][3])
    stored_file = store_path / "files" / uuid
    if stored_file.is_file():
        return
    password = index[uuid][0]
    wip_file_gpg = store_path / "wip" / f"{uuid}.gpg"
    wip_file = store_path / "wip" / uuid
    encrypted_file = store_path / "encrypted_files" / f"{uuid}.gpg"
    copy_file(encrypted_file, wip_file_gpg)
    decrypt_file(wip_file_gpg, password)
    copy_file(wip_file, stored_file)


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    conf = """~/.config/fv/init.json => {"stores": {"default": {"path": "path-that-will-include-the-subdirs"}}}"""
    output_lines = [
        "fv - File Vault",
        "───────────────",
        conf,
        "  - creates 4 subdirs:\n    - files\n    - encrypted_files\n    - index\n    - wip",
        "───────────────",
        "- fv i file_path         ==> encrypt with a single-use password, index, and store a file in /encrypted_files",
        "- fv o uuid              ==> recover an indexed file from /encrypted_files to /file using the uuid from i",
        "- fv [[path] OR [uuid]]  ==> retrieves if the argument is an uuid, else stores as path",
        "───────────────",
        "You can store any file and record its uuid in your knowledge base or any other external tool",
        "You can version /indexes and securely share it between your local devices",
        "You can remote sync /encrypted_files to many remote unsecure servers as those are encrypted and hashed",
        "You can symlink /files for easy access to your files",
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
