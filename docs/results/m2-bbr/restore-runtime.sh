#!/bin/bash
# Run from the later checkout; the expected manifest hash is in the results.
set -euo pipefail
expected=${1:?binary archive MANIFEST.sha256 digest is required}
[[ $expected =~ ^[0-9a-f]{64}$ ]]
image=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
archive=/data/m2/archive/m2c-bbr-769311e-runtime-a1
test -f tools/m2/matrix.py
docker run --rm --network none --name "utcp-bbr-live-restore-$$" --cpuset-cpus 16-31 --user "$(id -u):$(id -g)" -v utcp-data:/data:ro -v "$PWD:/checkout" "$image" nice -n 10 bash -ec '
  cd "$1"; echo "$2  MANIFEST.sha256" | sha256sum -c -
  sha256sum -c --quiet MANIFEST.sha256
  for spec in "utcp-bulk|apps/utcp-bulk/utcp-bulk" "libutcp_core.a|src/core/libutcp_core.a"; do
    source=${spec%|*}; dest="/checkout/build/tb-gcc-release/${spec#*|}"
    if [[ -e $dest ]]; then cmp "$source" "$dest"; else mkdir -p "$(dirname "$dest")"; cp -p "$source" "$dest"; fi
    cmp "$source" "$dest"; sha256sum "$dest"
  done' bash "$archive" "$expected"
python3 -B - <<'PY'
import sys
sys.path.insert(0,'tools/m2')
import matrix as m
d=m.static_meta()
want=dict(build='build/tb-gcc-release',uname_r='7.0.0-42-generic',
    bulk_sha256='6bf415a2a5745d356e4583d633327bc3d58f7b49a4ae2c47078fb54405acbc7d',
    core_sha256='c3d0fa75effdfc6215e5eb80db0e96cb196ccf79c4c3bffc0b2bce54e2e35d53',
    scripts_sha256='43bf359c7ba1bf5d40f3a58ef7c4c9e5ba82737038b6d25ba35aa52d55b72912',
    image_id='sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66')
assert all(d[k]==v for k,v in want.items()),d
print(d)
PY
