"""Record full QA against an exact commit, keeping generated logs outside Git."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    destination = ROOT / ".cache" / "final-qa" / sha
    destination.mkdir(parents=True, exist_ok=True)
    checks = [
        ("pytest", [sys.executable, "-m", "pytest", "-q", "-ra"]),
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
        ("diff", ["git", "diff", "--check"]),
        ("commit_diff", ["git", "show", "--format=", "--check", "HEAD"]),
    ]
    result = {"sha": sha, "started_utc": datetime.now(UTC).isoformat(), "checks": {},
              "live_llm_reexecuted": False,
              "limitations": ["Local Ollama was unavailable; historical actual replay is separate from new inference",
                              "Browser visual QA and MP4 recording were unavailable"]}
    for name, command in checks:
        print(f"Running {name} at {sha}", flush=True)
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False,
                                   encoding="utf-8", errors="replace",
                                   env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        (destination / f"{name}.txt").write_text(completed.stdout + completed.stderr, encoding="utf-8")
        result["checks"][name] = {"exit_code": completed.returncode, "command": command,
                                 "log": f"{name}.txt"}
        print(f"{name}: exit {completed.returncode}", flush=True)
    result["finished_utc"] = datetime.now(UTC).isoformat()
    result["passed"] = all(check["exit_code"] == 0 for check in result["checks"].values())
    (destination / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(destination)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
