import os
import secrets
import stat

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
IS_POSIX = os.name == "posix"
MAX_FILE_SIZE = 16 * 1024 * 1024


class SafeIOError(Exception):


def ensure_private_dir(path: str) -> None:
    if not os.path.lexists(path):
        os.makedirs(path, mode=0o700)
    st = os.lstat(path) 
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SafeIOError(f"{path} is not a plain directory (symlinks are rejected).")
    if IS_POSIX:
        if st.st_uid != os.getuid():
            raise SafeIOError(f"{path} is not owned by the current user.")
        if st.st_mode & 0o077:
            raise SafeIOError(
                f"{path} is accessible by other users. Fix with: chmod 700 '{path}'"
            )


def read_private_file(path: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | NOFOLLOW | CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise SafeIOError(f"Cannot open {path} safely (symlink or access error).") from exc
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise SafeIOError(f"{path} is not a regular file.")
        if IS_POSIX:
            if st.st_uid != os.getuid():
                raise SafeIOError(f"{path} is not owned by the current user.")
            if st.st_mode & 0o077:
                raise SafeIOError(
                    f"{path} has unsafe permissions. Fix with: chmod 600 '{path}'"
                )
        if st.st_size > MAX_FILE_SIZE:
            raise SafeIOError(f"{path} is unexpectedly large.")
        return f.read(MAX_FILE_SIZE + 1)


def atomic_write_private(path: str, data: bytes) -> None:
    directory = os.path.dirname(path) or "."
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise SafeIOError(f"{path} exists and is not a regular file.")
    except FileNotFoundError:
        pass

    tmp = os.path.join(directory, f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            if IS_POSIX:
                os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)


def _fsync_dir(directory: str) -> None:
    if not IS_POSIX:
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
