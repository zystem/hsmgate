#!/usr/bin/env python3
"""Map audit-only test sources into an existing checkout without changing it."""
import json
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
packages = {
    "internal/scheme/ecies": "ecies_test.go.txt",
    "internal/face/kmsjson": "kms_test.go.txt",
    "internal/sigv4": "sigv4_test.go.txt",
}
mapping = {str(root / package / "audit_crypto_test.go"): str(here / source)
           for package, source in packages.items()}
target = here / "overlay.json"
target.write_text(json.dumps({"Replace": mapping}, indent=2) + "\n")
print(target)
