# passmgr - CLI password manager (ICS0022)

A local, offline command-line password manager. Credentials are encrypted at rest with
AES-256-GCM; the vault is unlocked only by a master password (Argon2id). The interface never
prints stored passwords to the screen.

## Requirements

- Python 3.9 or newer
- Linux or macOS (Windows works, but file-permission and symlink checks are POSIX-only)

## Build and run (clean machine)

```bash
git clone https://github.com/Xnogst/ics0022.git
cd ics0022

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m passmgr init
python -m passmgr add github -u alice
python -m passmgr list
python -m passmgr get github --copy
```

Run the tests:

```bash
python -m unittest discover -v
```

## Commands

| Command | Description |
|---|---|
| `init` | Create a new vault (asks for the master password twice) |
| `add SERVICE [-u USER] [--generate] [--length N] [--notes TEXT] [--force]` | Add an entry. The password is typed hidden, or generated with `--generate` and never displayed |
| `list` | List service names and usernames |
| `get SERVICE [--copy] [--timeout S]` | Show username/notes; the password is shown as `********`. `--copy` puts it in the clipboard and clears it after 20 s |
| `delete SERVICE [--yes]` | Delete an entry (asks for confirmation) |
| `passwd` | Change the master password (re-wraps the master key; vault file untouched) |

Global option: `--dir PATH` (or env `PASSMGR_DIR`) selects the data directory; default `~/.config/passmgr`.

`--copy` needs one of `pbcopy`, `wl-copy`, `xclip`, `xsel` or `clip`. If none is installed, the command
fails instead of printing the password.

## Design summary

```
master password --Argon2id(t=3, m=64 MiB, p=4, 16-byte salt)--> KEK
KEK --AES-256-GCM--> wraps random 256-bit Master Key (MK)   -> keystore.json
MK  --AES-256-GCM (fresh 12-byte IV per save)--> vault JSON -> vault.enc
```

- `keystore.json`: version, salt, KDF parameters, IV, wrapped MK. KDF parameters and salt are
  bound as AEAD associated data; minimum **and maximum** bounds are enforced when loading.
- `vault.enc`: `"PMVR"` | version | 3 reserved bytes | 12-byte IV | ciphertext | 16-byte tag.
  The 8 header bytes are authenticated as AAD.
- All files are 0600 in a 0700 directory, opened with `O_NOFOLLOW`, checked with `fstat()`,
  and written atomically (temp file, `fsync`, `os.replace`).
- Every unlock failure (wrong password, tampering, malformed file) prints the same message:
  `Authentication failed or corrupted vault.`
- Core dumps are disabled; unexpected errors print a generic message without a stack trace.

## Source layout

```
passmgr/
  cli.py        argparse commands, hidden prompts, clipboard, error handling
  keystore.py   Argon2id KEK, MK wrap/unwrap, password policy, KDF bounds
  vault.py      vault file format, entry operations, store orchestration
  safeio.py     symlink-safe reads, permissions, atomic writes
  crypto.py     the only module that calls cryptography / argon2
tests/          unit and CLI tests (python -m unittest discover)
```

## Known limitations

- Zeroizing keys in Python is best-effort (`bytes` are immutable; libraries copy keys internally).
- No protection against rollback to an older valid `vault.enc`.
- `passwd` re-wraps the same Master Key; it does not rotate it.
- A compromised OS (keyloggers, root memory scraping) is out of scope.
