#!/usr/bin/env bash
# ri-seal release procedure — run by a maintainer, by hand, on a clean checkout. It does NOT push anything.
#
#   RISEAL_RELEASE_CONFIRM=yes RISEAL_RELEASE_DIR=~/ri-seal-release scripts/release.sh 0.2.0
#
# Steps
#   1. checks: clean tree, version in pyproject.toml and src/ri_seal/__init__.py equals the argument
#   2. git tag -s vX.Y.Z  (signed tag on the current commit; local only)
#   3. python -m build    → dist/ri_seal-X.Y.Z.tar.gz and dist/ri_seal-X.Y.Z-py3-none-any.whl
#   4. SHA256SUMS         → dist/SHA256SUMS (sha256 of both files)
#   5. self-seal          → copy dist files + SHA256SUMS into $RISEAL_RELEASE_DIR/vX.Y.Z/ and `ri-seal seal` them
#                           ($RISEAL_RELEASE_DIR is a ri-seal project initialised once with the publisher key,
#                            `ri-seal --dir $RISEAL_RELEASE_DIR init --privacy normal` — release file names are public)
#   6. anchor             → `ri-seal anchor` (sends only the 32-byte seal hash; see PRIVACY.md)
#   7. verify + export    → `ri-seal verify` then `ri-seal export ri-seal-vX.Y.Z-evidence.zip`
#   8. prints what a person must do next: push the tag, create the GitHub release, attach
#      the two dist files + SHA256SUMS + the evidence zip, write the commit hash into the README install line.
#
# Nothing in this script pushes, uploads or publishes. PyPI upload is not part of it.
set -euo pipefail

if [[ "${RISEAL_RELEASE_CONFIRM:-}" != "yes" ]]; then
  echo "refusing to run: set RISEAL_RELEASE_CONFIRM=yes (this script tags, builds and seals a release)" >&2
  exit 2
fi
VER="${1:?usage: scripts/release.sh X.Y.Z}"
REL="${RISEAL_RELEASE_DIR:?set RISEAL_RELEASE_DIR to an initialised ri-seal project folder}"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# 1. checks
if [[ -n "$(git status --porcelain)" ]]; then echo "working tree not clean" >&2; exit 1; fi
grep -q "^version = \"$VER\"" pyproject.toml || { echo "pyproject.toml version != $VER" >&2; exit 1; }
grep -q "__version__ = \"$VER\"" src/ri_seal/__init__.py || { echo "__init__ version != $VER" >&2; exit 1; }
[[ -f "$REL/.riseal/config.json" ]] || { echo "$REL is not a ri-seal project (run: ri-seal --dir $REL init --privacy normal)" >&2; exit 1; }
python -m pytest -q

# 2. signed tag (local)
git tag -s "v$VER" -m "ri-seal $VER"
COMMIT="$(git rev-parse HEAD)"

# 3. build (clear stale build/ and dist/ so old files never end up in the release or the checksums)
rm -rf build dist
python -m build

# 4. checksums
( cd dist && shasum -a 256 ri_seal-"$VER".tar.gz ri_seal-"$VER"-py3-none-any.whl > SHA256SUMS )
cat dist/SHA256SUMS

# 5. self-seal with ri-seal itself
OUT="$REL/v$VER"
mkdir -p "$OUT"
cp dist/ri_seal-"$VER".tar.gz dist/ri_seal-"$VER"-py3-none-any.whl dist/SHA256SUMS "$OUT/"
printf 'ri-seal %s\ncommit %s\n' "$VER" "$COMMIT" > "$OUT/RELEASE_COMMIT.txt"
ri-seal --dir "$REL" seal "v$VER" --note "ri-seal v$VER release (commit $COMMIT)"

# 6. external time anchor (optional network step: only the 32-byte seal hash leaves the machine)
ri-seal --dir "$REL" anchor || echo "anchor failed — re-run 'ri-seal --dir $REL anchor' later" >&2

# 7. verify and export the evidence bundle
ri-seal --dir "$REL" verify
ri-seal --dir "$REL" export "$ROOT/dist/ri-seal-v$VER-evidence.zip"

# 8. what a person does next (not automated on purpose)
cat <<EOF

Release v$VER prepared locally (commit $COMMIT). Nothing was pushed.
Next, by hand, after review:
  git push origin v$VER
  create the GitHub release v$VER and attach:
    dist/ri_seal-$VER.tar.gz  dist/ri_seal-$VER-py3-none-any.whl  dist/SHA256SUMS  dist/ri-seal-v$VER-evidence.zip
  install line for the README / release notes:
    pip install "ri-seal[anchor] @ git+https://github.com/leekangyeop-cpu/ri-seal@$COMMIT"
EOF
