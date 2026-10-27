#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version=//p' module.prop | head -n1)
OUT=${1:-"dist/nfqttl-${VERSION}-source.zip"}
mkdir -p "$(dirname "$OUT")"
OUT=$(readlink -f "$OUT")
python3 - "$OUT" <<'PY'
import sys,zipfile
from pathlib import Path
root=Path.cwd();dest=Path(sys.argv[1]);excluded={'target','dist','.git','__pycache__'}
with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in sorted(root.rglob('*')):
  rel=p.relative_to(root)
  if not p.is_file() or any(x in excluded for x in rel.parts):continue
  if rel.as_posix()=='libs/arm64-v8a/nfqttl':continue
  z.write(p,rel.as_posix())
print(dest)
PY
sha256sum "$OUT" > "$OUT.sha256"
