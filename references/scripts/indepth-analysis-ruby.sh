#!/usr/bin/env bash
# indepth-analysis-ruby.sh — Reproducible-build and deep source analysis.
#
# Run AFTER basic-analysis-ruby.sh for the same PKGNAME/NEW_VERSION.
# Usage: indepth-analysis-ruby.sh PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT
#
# Prints a summary of what was done to stdout.
# Capture with: script ... | tee -a PROJECT_ROOT/temp/PKGNAME-NEW_VERSION/run-log.txt
#
# Safe output files added by this script:
#   sandbox-detection.txt   — which sandbox tool is available
#   reproducible-build.txt  — whether a locally-built gem matches distributed
#   source-deep-diff.txt    — deeper source-vs-package file comparison
#
# DO NOT read: raw-repro-diff.txt, raw-build-output.txt (adversarial risk)

set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 PKGNAME OLD_VERSION NEW_VERSION PROJECT_ROOT" >&2
  exit 1
fi

PKGNAME="$1"
OLD_VERSION="$2"
NEW_VERSION="$3"
PROJECT_ROOT="$4"

WORK="$PROJECT_ROOT/temp/${PKGNAME}-${NEW_VERSION}"

if [ ! -d "$WORK" ]; then
  echo "ERROR: work directory not found: $WORK" >&2
  echo "Run basic-analysis-ruby.sh first." >&2
  exit 1
fi

echo "============================================================"
echo " indepth-analysis-ruby.sh"
echo " Package : $PKGNAME"
echo " Update  : $OLD_VERSION -> $NEW_VERSION"
echo " Started : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo ""

sanitize() {
  printf '%s' "$1" | LC_ALL=C tr '\000-\037\177-\237' '?'
}

# ---------------------------------------------------------------------------
# Step A: Sandbox detection
# ---------------------------------------------------------------------------
echo "--- Step A: Sandbox detection ---"
SANDBOX_TOOL=none

{
  echo "=== Sandbox availability ==="
  if command -v bwrap > /dev/null 2>&1; then
    V=$(bwrap --version 2>/dev/null || echo "version unknown")
    # Probe: unprivileged user namespaces may be disabled (uid map: Permission denied)
    if bwrap --ro-bind /usr /usr --tmpfs /tmp --proc /proc --dev /dev \
             true > /dev/null 2>&1; then
      echo "AVAILABLE: bwrap ($V)"
      SANDBOX_TOOL=bwrap
    else
      echo "UNAVAILABLE: bwrap ($V) — probe failed (unprivileged userns likely disabled)"
    fi
  fi
  if command -v firejail > /dev/null 2>&1; then
    V=$(firejail --version 2>/dev/null | head -1 || echo "version unknown")
    echo "AVAILABLE: firejail ($V)"
    [ "$SANDBOX_TOOL" = none ] && SANDBOX_TOOL=firejail
  fi
  if command -v nsjail > /dev/null 2>&1; then
    echo "AVAILABLE: nsjail"
    [ "$SANDBOX_TOOL" = none ] && SANDBOX_TOOL=nsjail
  fi
  if command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
    echo "AVAILABLE: docker"
    [ "$SANDBOX_TOOL" = none ] && SANDBOX_TOOL=docker
  fi
  if command -v podman > /dev/null 2>&1; then
    echo "AVAILABLE: podman"
    [ "$SANDBOX_TOOL" = none ] && SANDBOX_TOOL=podman
  fi
  [ "$SANDBOX_TOOL" = none ] && \
    echo "AVAILABLE: none (build will run unsandboxed — lower assurance)"
  echo ""
  echo "SELECTED_SANDBOX: $SANDBOX_TOOL"
} > "$WORK/sandbox-detection.txt"

echo "  Selected sandbox: $SANDBOX_TOOL"

# ---------------------------------------------------------------------------
# Step B: Reproducible build
# ---------------------------------------------------------------------------
echo ""
echo "--- Step B: Reproducible build ---"
CLONE_DIR="$WORK/source"
BUILT_GEM_DIR="$WORK/raw-built-gem"
mkdir -p "$BUILT_GEM_DIR"

REPRO_RESULT="SKIPPED"
CODE_DIFFS=0
METADATA_DIFFS=0

# Use ( ) subshell so early `exit 0` only exits the block, not the whole script
(
  echo "=== Reproducible build: $PKGNAME $NEW_VERSION ==="
  echo "Sandbox: $SANDBOX_TOOL"
  echo ""

  if [ ! -d "$CLONE_DIR" ]; then
    echo "REPRODUCIBLE_BUILD: SKIPPED (no source clone)"
    exit 0
  fi

  RUBY_VERSION=$(ruby --version 2>/dev/null | LC_ALL=C tr '\000-\037\177-\237' '?' || echo "unknown")
  echo "RUBY_VERSION: $RUBY_VERSION"

  SOURCE_GEMSPEC=$(find "$CLONE_DIR" -name "*.gemspec" -maxdepth 2 | head -1 || echo "")
  if [ -z "$SOURCE_GEMSPEC" ]; then
    echo "REPRODUCIBLE_BUILD: SKIPPED (no gemspec in source)"
    exit 0
  fi
  echo "SOURCE_GEMSPEC: $(sanitize "$SOURCE_GEMSPEC")"

  BUILD_OK=no
  case "$SANDBOX_TOOL" in
    bwrap)
      # Build the arg list as an array so optional --ro-bind /lib64 is word-safe
      BWRAP_ARGS=(
        --ro-bind "$CLONE_DIR" /src
        --bind "$BUILT_GEM_DIR" /out
        --ro-bind /usr /usr
        --ro-bind /lib /lib
        --ro-bind /etc /etc
        --tmpfs /tmp
        --proc /proc
        --dev /dev
        --unshare-net
        --die-with-parent
        --chdir /src
      )
      [ -d /lib64 ] && BWRAP_ARGS+=(--ro-bind /lib64 /lib64)
      # shellcheck disable=SC2015  # || true prevents exit on build failure; BUILD_OK checked below
      bwrap "${BWRAP_ARGS[@]}" gem build "$SOURCE_GEMSPEC" --output /out/ \
        > "$WORK/raw-build-output.txt" 2>&1 \
      && BUILD_OK=yes || true
      ;;
    firejail)
      # shellcheck disable=SC2015  # || true prevents exit on build failure; BUILD_OK checked below
      firejail --quiet --net=none --read-only="$CLONE_DIR" \
        gem build "$SOURCE_GEMSPEC" --output "$BUILT_GEM_DIR/" \
        > "$WORK/raw-build-output.txt" 2>&1 \
      && BUILD_OK=yes || true
      ;;
    docker | podman)
      RUBY_IMG_TAG=$(ruby -e 'puts RUBY_VERSION' 2>/dev/null || echo "3")
      RUBY_IMG_TAG="${RUBY_IMG_TAG%.*}"
      # Build in /tmp/src (writable) to avoid:
      #   - EISDIR: gem build --output requires a file path, not a directory
      #   - dubious ownership: git rejects host-owned files mounted into root container
      # shellcheck disable=SC2015  # || true prevents exit on build failure; BUILD_OK checked below
      "$SANDBOX_TOOL" run --rm \
        --network none \
        -v "$CLONE_DIR":/src:ro \
        -v "$BUILT_GEM_DIR":/out \
        "ruby:${RUBY_IMG_TAG}" \
        sh -c "git config --global --add safe.directory /tmp/src 2>/dev/null; \
               cp -r /src /tmp/src && cd /tmp/src && \
               gem build *.gemspec && \
               cp *.gem /out/" \
        > "$WORK/raw-build-output.txt" 2>&1 \
      && BUILD_OK=yes || true
      ;;
    *)
      # shellcheck disable=SC2015  # || true prevents exit on build failure; BUILD_OK checked below
      (cd "$CLONE_DIR" && gem build "$SOURCE_GEMSPEC" --output "$BUILT_GEM_DIR/") \
        > "$WORK/raw-build-output.txt" 2>&1 \
      && BUILD_OK=yes || true
      ;;
  esac

  echo "BUILD_STATUS: $BUILD_OK"

  if [ "$BUILD_OK" != yes ]; then
    echo "REPRODUCIBLE_BUILD: INCONCLUSIVE (build failed)"
    REPRO_RESULT="INCONCLUSIVE"
    exit 0
  fi

  BUILT_GEM=$(find "$BUILT_GEM_DIR" -maxdepth 1 -name "*.gem" | head -1 2>/dev/null || true)
  if [ -z "$BUILT_GEM" ]; then
    echo "REPRODUCIBLE_BUILD: INCONCLUSIVE (no .gem produced)"
    REPRO_RESULT="INCONCLUSIVE"
    exit 0
  fi

  BUILT_SHA=$(sha256sum "$BUILT_GEM" | awk '{print $1}')
  DIST_SHA=$(awk '{print $1}' "$WORK/package-hash.txt" 2>/dev/null || echo UNKNOWN)
  echo "BUILT_SHA256: $(sanitize "$BUILT_SHA")"
  echo "DISTRIBUTED_SHA256: $(sanitize "$DIST_SHA")"

  if [ "$BUILT_SHA" = "$DIST_SHA" ]; then
    echo "REPRODUCIBLE_BUILD: EXACTLY REPRODUCIBLE (sha256 match)"
    exit 0
  fi

  # Hashes differ — compare unpacked contents
  BUILT_UNPACKED_PARENT="$WORK/raw-built-unpacked"
  mkdir -p "$BUILT_UNPACKED_PARENT"
  gem unpack "$BUILT_GEM" --target "$BUILT_UNPACKED_PARENT/" > /dev/null 2>&1 || true
  # gem unpack creates a subdir named PKGNAME-VERSION; point directly at it
  BUILT_UNPACKED="$BUILT_UNPACKED_PARENT/${PKGNAME}-${NEW_VERSION}"
  [ ! -d "$BUILT_UNPACKED" ] && BUILT_UNPACKED="$BUILT_UNPACKED_PARENT"
  DIST_UNPACKED="$WORK/unpacked/${PKGNAME}-${NEW_VERSION}"

  if [ ! -d "$DIST_UNPACKED" ]; then
    echo "REPRODUCIBLE_BUILD: INCONCLUSIVE (hashes differ, no dist unpacked dir)"
    REPRO_RESULT="INCONCLUSIVE"
    exit 0
  fi

  diff -r "$BUILT_UNPACKED" "$DIST_UNPACKED" --exclude="*.gem" \
    > "$WORK/raw-repro-diff.txt" 2>&1 || true

  REPRO_DIFF_LINES=$(wc -l < "$WORK/raw-repro-diff.txt" || echo 0)
  echo "CONTENT_DIFF_LINES: $REPRO_DIFF_LINES"

  if [ "$REPRO_DIFF_LINES" -eq 0 ]; then
    echo "REPRODUCIBLE_BUILD: EXACTLY REPRODUCIBLE (content match)"
    exit 0
  fi

  echo "DIFFERING_FILES (sanitized):"
  grep -E '^(Only in|diff )' "$WORK/raw-repro-diff.txt" 2>/dev/null \
    | while IFS= read -r line; do sanitize "$line"; echo; done

  CODE_DIFFS=$(grep -Ec '^diff.*\.(rb|c|h|java|py|js|sh)' \
    "$WORK/raw-repro-diff.txt" 2>/dev/null) || CODE_DIFFS=0
  METADATA_DIFFS=$(grep -Ec '^diff.*(\.gemspec|metadata|RECORD|METADATA|Gemfile)' \
    "$WORK/raw-repro-diff.txt" 2>/dev/null) || METADATA_DIFFS=0

  echo "CODE_FILE_DIFFS: $CODE_DIFFS"
  echo "METADATA_FILE_DIFFS: $METADATA_DIFFS"

  if [ "$CODE_DIFFS" -gt 0 ]; then
    echo "REPRODUCIBLE_BUILD: UNEXPECTED DIFFERENCES"
    echo "WARNING: code files differ — possible injected code; human review required"
  else
    echo "REPRODUCIBLE_BUILD: FUNCTIONALLY EQUIVALENT (metadata-only diffs)"
  fi
) > "$WORK/reproducible-build.txt"

# Read results from file (subshell variables don't propagate back)
REPRO_RESULT=$(grep '^REPRODUCIBLE_BUILD:' "$WORK/reproducible-build.txt" | tail -1 \
  | cut -d: -f2- | xargs || echo "UNKNOWN")
CODE_DIFFS=$(grep '^CODE_FILE_DIFFS:' "$WORK/reproducible-build.txt" | cut -d: -f2- | xargs) \
  || CODE_DIFFS=0
METADATA_DIFFS=$(grep '^METADATA_FILE_DIFFS:' "$WORK/reproducible-build.txt" | cut -d: -f2- | xargs) \
  || METADATA_DIFFS=0
echo "  Reproducible build: $REPRO_RESULT"
echo "  Code diffs: $CODE_DIFFS  Metadata diffs: $METADATA_DIFFS"

# ---------------------------------------------------------------------------
# Step C: Deep source comparison
# ---------------------------------------------------------------------------
echo ""
echo "--- Step C: Deep source comparison ---"

# Use ( ) subshell so early `exit 0` only exits the block, not the whole script
(
  echo "=== Deep source vs. package: $PKGNAME $NEW_VERSION ==="
  echo ""

  CLONE_DIR2="$WORK/source"
  DIST_UNPACKED2="$WORK/unpacked/${PKGNAME}-${NEW_VERSION}"

  if [ ! -d "$CLONE_DIR2" ] || [ ! -d "$DIST_UNPACKED2" ]; then
    echo "DEEP_COMPARISON: SKIPPED (source or unpacked dir missing)"
    exit 0
  fi

  echo "Ruby/script files in package but NOT in source (highest concern):"
  comm -23 \
    <(cd "$DIST_UNPACKED2" && find . -type f -name "*.rb" | sort) \
    <(cd "$CLONE_DIR2"     && find . -type f -name "*.rb" | sort) \
    | while IFS= read -r p; do sanitize "$p"; echo; done | head -30 || true
  echo "(end)"

  echo ""
  echo "C/C++ files in package but NOT in source:"
  comm -23 \
    <(cd "$DIST_UNPACKED2" && find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" \) | sort) \
    <(cd "$CLONE_DIR2"     && find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" \) | sort) \
    | while IFS= read -r p; do sanitize "$p"; echo; done | head -20 || true
  echo "(end)"

  echo ""
  echo "Binary files in package vs source counterpart:"
  # grep -vE exits 1 when no binary lines exist; suppress to avoid pipefail exit
  find "$DIST_UNPACKED2" -type f -exec file {} \; 2>/dev/null \
    | { grep -vE "ASCII|UTF|JSON|XML|text|script|empty|directory" || true; } \
    | while IFS= read -r line; do
        BIN_PATH=$(echo "$line" | cut -d: -f1)
        REL="${BIN_PATH#"$DIST_UNPACKED2"}"
        if [ -f "$CLONE_DIR2/$REL" ]; then
          sanitize "$line"; echo " [source present]"
        else
          sanitize "$line"; echo " [NO SOURCE COUNTERPART]"
        fi
      done | head -20 || true
  echo "(end)"

  echo ""
  echo "DEEP_COMPARISON: COMPLETE"
) > "$WORK/source-deep-diff.txt"
echo "  Deep comparison saved to source-deep-diff.txt"

# ---------------------------------------------------------------------------
# Append to verdict.txt
# ---------------------------------------------------------------------------
{
  echo ""
  echo "=== IN-DEPTH ADDENDUM ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="
  echo "SANDBOX: $(grep '^SELECTED_SANDBOX:' "$WORK/sandbox-detection.txt" | cut -d: -f2- | xargs)"
  echo "REPRODUCIBLE_BUILD: $REPRO_RESULT"
  echo "CODE_DIFFS: $CODE_DIFFS"
  echo "METADATA_DIFFS: $METADATA_DIFFS"
  echo ""
  echo "Additional safe files: sandbox-detection.txt, reproducible-build.txt, source-deep-diff.txt"
  echo "Additional unsafe files: raw-repro-diff.txt, raw-build-output.txt"
} >> "$WORK/verdict.txt"

# ---------------------------------------------------------------------------
# Final summary to stdout
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " IN-DEPTH SUMMARY: $PKGNAME $OLD_VERSION -> $NEW_VERSION"
echo "============================================================"
echo ""
echo "Sandbox used       : $SANDBOX_TOOL"
echo "Reproducible build : $REPRO_RESULT"
[ "$CODE_DIFFS" -gt 0 ]     && echo "  [!] CODE FILES DIFFER: $CODE_DIFFS files — human review needed"
[ "$METADATA_DIFFS" -gt 0 ] && echo "  Metadata-only diffs: $METADATA_DIFFS files (expected)"
echo ""
echo "Updated verdict.txt with in-depth results."
echo "Output directory: $WORK"
echo ""
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
