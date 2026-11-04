"""Validate and import a reviewed ZIP to an explicit local-only directory."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo.reviewed_package import import_archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    proof = import_archive(args.source, args.output)
    print(
        json.dumps(
            {
                k: proof[k]
                for k in (
                    "status",
                    "file_count",
                    "zip_sha256",
                    "runtime_execution_verified",
                    "raw_trial_recalculation_performed_here",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
