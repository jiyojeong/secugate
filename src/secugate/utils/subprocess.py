from __future__ import annotations
import subprocess
from typing import Sequence

def run_cmd(
    cmd: Sequence[str],
    cwd=None,
    capture_output=False,
    allow_error=False,
) -> str:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=capture_output,
    )
    if proc.returncode != 0 and not allow_error: 
        raise RuntimeError(
            f"커맨드 실패 ({proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}\n"
        )
    if capture_output:
              # checkov는 stderr에도 뱉는 경우가 있어서 둘 다 합쳐줌
        return (proc.stdout or "") + (proc.stderr or "")
    return ""