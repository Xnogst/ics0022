# Checkpoint 2 - progress note

**Project:** passmgr, a CLI password manager (Python)

## What works
- **Vault storage:** `init` creates `keystore.json` + `vault.enc`; entries can be added, listed, read and deleted.
- **Encryption at rest:** vault JSON encrypted with AES-256-GCM under a random Master Key; the Master Key is
  wrapped by an Argon2id-derived key. Verified by tests that no password, username or service name appears in either file.
- **Master password authentication:** the vault opens only if the GCM tag verifies. Wrong password, tampering and
  malformed files all give the same generic error.
- **Interface:** hidden prompts (`getpass`); stored passwords are never printed (`get` shows `********`; `--copy` uses the clipboard
  with auto-clear; `--generate` stores a random password without displaying it).
- **Safe file handling:** 0600/0700 permissions, `O_NOFOLLOW`, `fstat` checks, atomic writes.
- **Build/run:** `requirements.txt` plus instructions in README; 45 automated tests.

## Changes from the original design
- Moved the repository from the C++/CMake plan to Python, as in the design document.
- Interface is subcommands (`passmgr add ...`) rather than an interactive menu.

## Not done yet
- Edit command, rollback protection, clipboard handling on every platform, packaging as an installable `passmgr` command.

## Next
- Review and harden against the threat model; extend tests; final documentation.
