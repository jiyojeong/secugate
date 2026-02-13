import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_dir_hash(directory: Path) -> str:
    """
    Calculates a SHA256 hash of all .tf and .tfvars files in a directory.
    The hash is based on file paths and contents, ensuring that changes
    to either will result in a new hash.
    """
    hasher = hashlib.sha256()

    files_to_hash = sorted(list(directory.glob("**/*.tf"))) + sorted(
        list(directory.glob("**/*.tfvars"))
    )

    for file_path in files_to_hash:
        relative_path = file_path.relative_to(directory)
        hasher.update(str(relative_path).encode("utf-8"))

        hasher.update(file_path.read_bytes())

    return hasher.hexdigest()
