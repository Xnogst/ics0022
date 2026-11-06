"""Command-line interface. Passwords are read with getpass and never printed."""

import argparse
import getpass
import os
import secrets
import shutil
import string
import subprocess
import sys
import time

from . import crypto, keystore, safeio, vault
from .crypto import AuthFailure
from .vault import UserError

DEFAULT_DIR = os.path.join("~", ".config", "passmgr")
CLIPBOARD_SECONDS = 20


# ---------- helpers ----------

def harden_process() -> None:
    """Private umask and no core dumps (threat K2)."""
    os.umask(0o077)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def read_secret(prompt: str) -> str:
    if not sys.stdin.isatty():
        raise UserError("An interactive terminal is required to enter passwords.")
    return getpass.getpass(prompt)


def read_new_secret(prompt: str, confirm_prompt: str = "Repeat: ") -> str:
    first = read_secret(prompt)
    if first != read_secret(confirm_prompt):
        raise UserError("The two entries did not match.")
    return first


def generate_password(length: int = 20) -> str:
    if not 12 <= length <= 128:
        raise UserError("Generated password length must be between 12 and 128.")
    symbols = "!@#$%^&*()-_=+[]{};:,.?"
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, symbols]
    alphabet = "".join(pools)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw


def _clipboard_command():
    """Return an argv that reads text from stdin into the clipboard, or None."""
    candidates = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip"],
    ]
    for argv in candidates:
        if shutil.which(argv[0]):
            return argv
    return None


def set_clipboard(text: str) -> bool:
    argv = _clipboard_command()
    if argv is None:
        return False
    try:  # text goes through stdin, never through argv / the process list (A4)
        subprocess.run(argv, input=text.encode("utf-8"), check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _directory(args) -> str:
    return os.path.abspath(os.path.expanduser(args.dir))


# ---------- commands ----------

def cmd_init(args) -> int:
    directory = _directory(args)
    password = read_new_secret("Choose master password: ", "Repeat master password: ")
    vault.init_store(directory, password)
    print(f"Vault created in {directory}")
    return 0


def cmd_add(args) -> int:
    directory = _directory(args)
    master = read_secret("Master password: ")
    with vault.open_store(directory, master) as session:
        if args.generate:
            secret = generate_password(args.length)
            print("A strong password was generated and stored (not displayed).")
        else:
            secret = read_new_secret(f"Password for '{args.service}': ")
        notes = args.notes or ""
        vault.add_entry(session.payload, args.service, args.username or "", secret,
                        notes, overwrite=args.force)
        session.save()
    print(f"Saved '{args.service.strip()}'.")
    return 0


def cmd_list(args) -> int:
    master = read_secret("Master password: ")
    with vault.open_store(_directory(args), master) as session:
        rows = vault.list_entries(session.payload)
    if not rows:
        print("(vault is empty)")
    for name, username in rows:
        print(f"{name}" + (f"  [{username}]" if username else ""))
    return 0


def cmd_get(args) -> int:
    master = read_secret("Master password: ")
    with vault.open_store(_directory(args), master) as session:
        entry = vault.get_entry(session.payload, args.service)
        print(f"Service:  {args.service.strip()}")
        print(f"Username: {entry['username']}")
        print("Password: ******** (hidden)")
        if entry.get("notes"):
            print(f"Notes:    {entry['notes']}")
        if not args.copy:
            print("Use --copy to copy the password to the clipboard.")
            return 0
        if not set_clipboard(entry["password"]):
            raise UserError("No clipboard tool found (pbcopy, wl-copy, xclip, xsel or clip). "
                            "Passwords are never printed to the screen.")
    print(f"Password copied. Clipboard clears in {args.timeout}s (Ctrl+C to clear now).")
    try:
        time.sleep(args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        set_clipboard("")
    print("Clipboard cleared.")
    return 0


def cmd_delete(args) -> int:
    master = read_secret("Master password: ")
    with vault.open_store(_directory(args), master) as session:
        vault.get_entry(session.payload, args.service)  # fail early if missing
        if not args.yes:
            answer = input(f"Type the service name '{args.service.strip()}' to confirm deletion: ")
            if answer.strip() != args.service.strip():
                raise UserError("Cancelled.")
        vault.delete_entry(session.payload, args.service)
        session.save()
    print(f"Deleted '{args.service.strip()}'.")
    return 0


def cmd_passwd(args) -> int:
    old = read_secret("Current master password: ")
    new = read_new_secret("New master password: ", "Repeat new master password: ")
    vault.change_password(_directory(args), old, new)
    print("Master password changed. The vault itself was not modified.")
    return 0


# ---------- entry point ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passmgr", description="Local encrypted password manager.")
    p.add_argument("--dir", default=os.environ.get("PASSMGR_DIR", DEFAULT_DIR),
                   help="data directory (default: ~/.config/passmgr)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    a = sub.add_parser("add", help="add an entry")
    a.add_argument("service")
    a.add_argument("--username", "-u", default="")
    a.add_argument("--notes", default="")
    a.add_argument("--generate", "-g", action="store_true", help="generate a random password")
    a.add_argument("--length", type=int, default=20, help="length for --generate")
    a.add_argument("--force", action="store_true", help="replace an existing entry")
    a.set_defaults(func=cmd_add)

    sub.add_parser("list", help="list services").set_defaults(func=cmd_list)

    g = sub.add_parser("get", help="show an entry (password stays hidden)")
    g.add_argument("service")
    g.add_argument("--copy", "-c", action="store_true", help="copy password to clipboard")
    g.add_argument("--timeout", type=int, default=CLIPBOARD_SECONDS,
                   help="seconds before the clipboard is cleared")
    g.set_defaults(func=cmd_get)

    d = sub.add_parser("delete", help="delete an entry")
    d.add_argument("service")
    d.add_argument("--yes", "-y", action="store_true", help="skip confirmation")
    d.set_defaults(func=cmd_delete)

    sub.add_parser("passwd", help="change the master password").set_defaults(func=cmd_passwd)
    return p


def main(argv=None) -> int:
    harden_process()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except AuthFailure:
        print(crypto.GENERIC_AUTH_ERROR, file=sys.stderr)
        return 1
    except (UserError, keystore.PasswordPolicyError, safeio.SafeIOError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception:  # no stack traces: they could expose secrets (O2)
        print("Error: the operation failed.", file=sys.stderr)
        return 1
