# Archive Extraction Security

This document records the security analysis of archive extraction for
this skill, so that future contributors do not have to rediscover the same
issues.

## Why we extract in Python rather than with system tools

System utilities such as `unzip`, `tar`, and `gem unpack` are convenient
but do not provide portable, reliable defences against adversarial archives.
The packages this skill analyses may be deliberately malicious, so we need
stronger guarantees than those tools offer.  The specific gaps are:

### 1. No portable byte-quota enforcement (CWE-409 - decompression bombs)

A "zip bomb" or "tar bomb" is a small, highly compressed archive that
expands to many gigabytes.  Neither `unzip` nor `tar` has a portable
command-line flag that enforces a cap on total uncompressed bytes.
Workarounds such as `ulimit -f` apply to the shell session, not reliably
to subprocesses, and vary across operating systems and container runtimes.

By streaming each entry ourselves in 64 KB chunks and accumulating a
running byte counter we can abort the moment the total crosses 1 GB
(`_MAX_EXTRACTED_SIZE`), without ever writing the excess bytes.  The same
loop enforces a maximum file count (`_MAX_EXTRACTED_FILES = 10_000`).

### 2. Symlink entries create a TOCTOU race window (CWE-22)

A malicious archive can contain:

```
symlink entry:  A  ->  /etc/passwd
regular entry:  A/shadow  (content: attacker-controlled)
```

When a system tool writes the symlink first, and then follows it while
writing the subsequent entry, it overwrites `/etc/passwd` (or any other
path the process can write).  The post-extraction call to
`remove_symlinks()` is too late: the overwrite has already happened.

By skipping symlink entries entirely at extraction time we eliminate the
race window.  There is no symlink to follow, so the subsequent
`A/shadow` entry either hits a missing directory (and is skipped or
raises) or is written into a benign local path.

### 3. Consistent, auditable policy in one place

Shell-flag equivalents differ between GNU and BSD variants of `tar` and
`unzip`.  Embedding the policy in Python makes it uniform across
platforms and easy to audit.

## Format-specific findings

### ZIP (`.whl`, `.zip` - `extract_zip_securely()`)

| Concern | Analysis |
|---|---|
| Path traversal | `zipfile` strips leading `/` from member names, but does NOT strip `..` components on all Python versions.  We call `_is_safe_extract_path()` on every entry. |
| Symlinks | Python's `zipfile.extractall()` creates symlinks when the ZIP entry has Unix external_attr with file type `0o120000` (S_IFLNK).  We check `(external_attr >> 16) & 0xFFFF` for this type and skip such entries. |
| Windows external_attr | On Windows-created ZIPs, `external_attr` stores MS-DOS attributes in the low 16 bits and the Unix mode bits are zero.  When `unix_mode == 0` our symlink check evaluates to False (the `if unix_mode and ...` guard), so the entry is treated as a regular file.  This is the correct behaviour: MS-DOS archives have no symlink concept. |
| Decompression bombs | `zipfile.ZipInfo.file_size` reports the uncompressed size from the local header, but this field can be forged.  We do NOT rely on it; instead we count actual bytes written. |
| Directory traversal via encoding | `_is_safe_extract_path()` calls `Path.resolve()` which normalises `..` components and returns an absolute path.  We then check that the result starts with `str(base) + os.sep`, using `os.sep` rather than `/` to avoid matching a path like `/base_extension/file`. |

#### `zipfile.extractall()` vs. our implementation

`zipfile.extractall()` was replaced because:
- It creates symlinks without any filtering.
- It has no size limit.
- It does not check paths on older Python versions.

### TAR (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz` - `tarfile_extractall_safe()`)

| Concern | Analysis |
|---|---|
| Symlinks | `tarfile.TarInfo.type == tarfile.SYMTYPE` marks a symlink.  We check `m.linkname` (non-empty on both symlinks and hardlinks) and `m.isfile()` (False for symlinks, hardlinks, devices, fifos).  Together these exclude all non-regular-file members except directories, which we handle separately. |
| Hardlinks | `m.isfile()` is False for hardlinks (`type == LNKTYPE`); they are excluded. |
| Device/FIFO/socket nodes | All have `m.isfile() == False`; excluded. |
| Decompression bombs | Same streaming approach as ZIP: bytes are counted as written. |
| Path traversal | Callers strip the top-level directory from member names and filter `..` components before passing the member list.  `tarfile_extractall_safe()` adds a belt-and-suspenders path check and raises `ArchiveSecurityError` if a path escapes `target_dir` or cannot be resolved at all, as both are attack signals. |
| Python 3.12 `filter='data'` | The built-in `filter='data'` policy (Python 3.12+) safely handles symlinks and path traversal, but provides no byte-count enforcement.  Our streaming implementation covers Python 3.10+ uniformly and adds the byte quota, so we no longer branch on the Python version. |

#### `tf.extractall(filter='data')` vs. our implementation

`filter='data'` was previously used for Python 3.12+ because it handles
symlinks.  Replaced because it still allows decompression bombs and
requires a Python version branch.

### GEM (`.gem` - Ruby, `hooks_ruby.py`)

Ruby gem archives are TAR files containing two inner tarballs
(`metadata.gz` and `data.tar.gz`).  The `gem unpack` command is a system
tool; we cannot easily stream its output.  Mitigations in place:

- `remove_symlinks()` is called on the unpacked directory.  Any symlinks
  found are removed and their count is reported as a `SECURITY_VIOLATION:`
  failure (symlinks in gems are a strong attack signal, not a benign
  feature).
- The `gem unpack` command itself is passed the gem path after `--` to
  prevent flag injection.
- We do not currently enforce a byte-quota on gem extraction.  This is a
  known gap; the recommended mitigation is to run the skill inside a
  sandbox (bwrap/firejail/docker) with a limited-size tmpfs mount.

## Path-traversal check: `_is_safe_extract_path()`

```python
resolved = (base_dir / member_path).resolve()
base = base_dir.resolve()
return str(resolved) == str(base) or str(resolved).startswith(str(base) + os.sep)
```

Key properties:

- `resolve()` on Python 3.6+ works even if the final path component does
  not yet exist: it resolves the existing prefix and appends the
  non-existing tail without following symlinks for the missing parts.
- The `+ os.sep` suffix in the prefix check prevents a directory named
  `/safe` from accidentally matching `/safe_extra/file` (the resolved
  string `/safe_extra/file` does NOT start with `/safe/`).
- Exceptions from `resolve()` (e.g. permission errors on a parent
  directory) return False (treat as unsafe).

## Security violation signaling

When any of the above checks fires, the failure is recorded in the
`failures` list with a `SECURITY_VIOLATION:` prefix.  This prefix is
detected by `write_signals()` in `dep_review.py`, which:

1. Adds `ARCHIVE_SECURITY_VIOLATION(N)` to the risk flags visible in
   `signals.txt`.
2. Appends a CRITICAL-level concern describing the violation, because
   legitimate packages do not contain zip bombs, path-traversal payloads,
   or symlinks outside the archive tree.

## Limits and why those values

| Constant | Value | Rationale |
|---|---|---|
| `_MAX_EXTRACTED_SIZE` | 1 GB | Large enough for any realistic package; small enough to prevent disk-fill on typical developer machines.  Adjust if a legitimate ecosystem regularly produces packages larger than 1 GB. |
| `_MAX_EXTRACTED_FILES` | 10,000 | Far above any realistic package.  npm's largest packages in the wild have a few thousand files; Python wheels rarely exceed a few hundred. |
| `_EXTRACT_CHUNK` | 64 KB | Standard I/O buffer size; balances syscall overhead against per-iteration work. |
