FAST_KDF = {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}  # the enforced minimum
MASTER = "Correct-Horse-9!"


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()
