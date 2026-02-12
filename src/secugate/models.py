from dataclasses import dataclass
from typing import Literal

Result = Literal["PASS", "FAIL", "SKIP"]


@dataclass
class Finding:
    """Represents a single finding from a security scanner."""

    framework: str
    check_id: str
    check_name: str
    result: Result
    resource: str
    file_path: str | None
    repo_file_path: str | None
    file_line_range: str | None
    severity: str | None
    guideline: str | None
    code_block: str | None
