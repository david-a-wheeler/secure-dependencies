# Ruby / Bundler / RubyGems Ecosystem Reference

Reference for the `securely-update-dependencies` skill, Ruby-specific details.

## Identifying Outdated Gems

```bash
# Show outdated gems respecting version constraints in Gemfile
bundle outdated --strict

# Show all outdated gems ignoring Gemfile constraints (shows what's possible)
bundle outdated

# Check for gems with known CVEs
bundle audit check --update
```

The `bundle audit` output lists gems with CVEs and their patch-level updates.
Prioritize security fixes from `bundle audit` over cosmetic version bumps.

## Downloading Without Installing

```bash
# Create isolated review directory
mkdir -p temp/dep-review

# Download the .gem file (no code runs)
gem fetch GEMNAME -v VERSION --output temp/dep-review/

# Unpack (no code runs; does not execute extconf.rb or Rakefile)
gem unpack temp/dep-review/GEMNAME-VERSION.gem --target temp/dep-review/unpacked/

# The gem source is now at:
# temp/dep-review/unpacked/GEMNAME-VERSION/
```

Note: `gem unpack` does **not** run `extconf.rb` or compile native extensions.
`gem install` does. Keep these separate.

## Gemspec Security Checklist

```bash
cat temp/dep-review/unpacked/GEMNAME-VERSION/GEMNAME.gemspec
```

Check each field:

| Field | What to look for |
|---|---|
| `extensions` | Any entry means native C/Java code compiles at `gem install`. Inspect `ext/` directory. |
| `executables` | Files added to the user's PATH. Read each one in `bin/`. |
| `post_install_message` | Should be plain release notes. Flag if it contains scripts, URLs, or instructions. |
| `add_runtime_dependency` | New transitive deps? Loosened constraints (`>= 0`, `> 0`)? |
| `add_development_dependency` | Usually lower risk but worth noting. |
| `files` | Does it include files outside `lib/`, `bin/`, `exe/`? Extra `.rb` at root level? |
| `homepage` | Still points to the same project? Not a new domain? |
| `authors` / `email` | Same maintainer as before? |

## Native Extension Inspection

If `extensions` is present in the gemspec, inspect the C source:

```bash
ls temp/dep-review/unpacked/GEMNAME-VERSION/ext/
cat temp/dep-review/unpacked/GEMNAME-VERSION/ext/*/extconf.rb
```

In `extconf.rb`, flag:
- `system(...)` calls (runs shell commands during compilation)
- Network requests (fetching external binaries)
- Writing files outside the gem's own `ext/` directory

In C source files (`.c`), flag:
- `system()`, `execve()`, `popen()`: arbitrary command execution
- `socket()`, `connect()`: network connections
- Reading environment variables for credentials: `getenv("AWS_SECRET_KEY")` etc.

## Rakefile Inspection

```bash
cat temp/dep-review/unpacked/GEMNAME-VERSION/Rakefile 2>/dev/null
```

Some gems use Rake tasks that run at install time. Flag:
- Any task named `install`, `post_install`, or similar
- Network downloads within tasks
- Writes to locations outside the gem directory

## Comparing Versions

Find the previous version in the local gem cache:

```bash
# Find gem cache location
gem environment gemdir
# Usually: /home/USER/.gem/ruby/VERSION/cache/

ls $(gem environment gemdir)/cache/ | grep GEMNAME
```

Unpack the old version alongside the new one and diff:

```bash
gem unpack $(gem environment gemdir)/cache/GEMNAME-OLDVERSION.gem \
  --target temp/dep-review/old/
diff -r temp/dep-review/old/GEMNAME-OLDVERSION \
  temp/dep-review/unpacked/GEMNAME-NEWVERSION \
  --exclude="*.gem"
```

## Checking RubyGems Metadata

```bash
# Show gem info from the remote index
gem info GEMNAME -r

# See all versions with publication dates
gem list GEMNAME -r -a
```

Online checks (manual, in browser or curl):
- Ownership: `https://rubygems.org/gems/GEMNAME/owners`
- Version history: `https://rubygems.org/gems/GEMNAME/versions`
- Compare two versions: some UIs provide diffs

## Gem Signing Verification

RubyGems supports cryptographic signing, though it is rarely used in practice.

```bash
# Check if gem is signed
gem install GEMNAME -v VERSION --trust-policy HighSecurity --dry-run
```

Trust policies:
- `NoSecurity`: no verification (default)
- `LowSecurity`: verifies if signed, accepts unsigned
- `MediumSecurity`: verifies signatures, allows untrusted signers
- `HighSecurity`: requires trusted signed gems

For most gems, signing is not available. Note the absence as a risk factor
(cannot cryptographically verify provenance) but do not block installation on it alone.

## Applying Updates Safely

Update gems **by name**, never with a bare `bundle update`:

```bash
# Good: updates only the specified gems
bundle update GEMNAME1 GEMNAME2

# Dangerous: updates everything at once, bypassing per-gem review
bundle update   # DO NOT run this
```

After updating, run the full audit:

```bash
bundle audit check
```

And run the project's test suite to catch behavioral regressions.

## Committing Lock File Updates

Commit `Gemfile.lock` in a standalone commit so the dependency update is
auditable separately from application code changes:

```bash
git add Gemfile.lock
git commit --signoff -m "chore: update GEMNAME vOLD -> vNEW\n\nSecurity analysis performed; no malicious patterns detected."
```

## Common False Positives

Not every match on the dangerous pattern checks is malicious.
Use judgment and read surrounding context:

| Pattern | Legitimate use | Red flag |
|---|---|---|
| `eval` | ERB/template engines, DSLs like RSpec | `eval(Base64.decode64(...))` |
| `system` | Gems that wrap CLI tools (e.g., git, imagemagick) | System calls in install hooks or on `require` |
| `Net::HTTP` | HTTP client gems, API wrappers | HTTP calls at `require` time or in install hooks |
| `ENV[...]` | Reading `RAILS_ENV`, `HOME`, `PATH` | Reading `AWS_SECRET`, `GITHUB_TOKEN` at load time |
| `define_method` | Metaprogramming DSLs | `define_method` with names from external data |
| `Open3` | Test helpers, wrapper gems for external tools | `Open3` calls during `require` |
| Non-ASCII in strings | Locale strings, UTF-8 content | Non-ASCII in **identifiers** (method/variable names) |
