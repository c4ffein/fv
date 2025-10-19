# fv
KISS Python e2e encrypted FileVault based on `gpg`

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
- If you want a production-ready e2e cloud with many features, check [github.com/Scille/parsec-cloud](https://github.com/Scille/parsec-cloud)
  - Ngl they should rename it tho
- **No auto ACL management for Windows paths**

## Help
```
fv - File Vault
───────────────
~/.config/fv/init.json => {"stores": {"default": {"path": "path-that-will-include-the-subdirs"}}}
  - creates 4 subdirs:
    - files
    - encrypted_files
    - index
    - wip
───────────────
- fv i file_path         ==> encrypt with a single-use password, index, and store a file in /encrypted_files
- fv o uuid              ==> recover an indexed file from /encrypted_files to /file using the uuid from i
- fv [[path] OR [uuid]]  ==> retrieves if the argument is an uuid, else stores as path
───────────────
You can store any file and record its uuid in your knowledge base or any other external tool
You can version /indexes and securely share it between your local devices
You can remote sync /encrypted_files to many remote unsecure servers as those are encrypted and hashed
You can symlink /files for easy access to your files
```
