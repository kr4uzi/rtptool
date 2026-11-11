# rtptool

Inspect, extract, and apply RTPatch `.rtp` binary patch files.

> Licensed under [MIT](LICENSE). The RTPatch format is undocumented. The binary layout, codec, and opcode semantics were
> reverse-engineered with Claude (Anthropic). See [SPEC.md](SPEC.md) for the full format description.

## Supported formats

- **0x0209 and earlier:** the original parsing and MODIFY application path,
  covered by a synthetic regression test.
- **0x0320:** the extra-entry layout with HISTORY chains (successive versions of
  one file), automatic selection of the matching intermediate source version,
  inherited source descriptors, full-file ADD and DELETE records, and exact
  decompression with strict size and checksum validation. Framing and flag
  combinations that have not been observed are rejected rather than guessed.
  See [SPEC-0x0320.md](SPEC-0x0320.md) for the layout and its open questions.

For 0x0320, the file size, both length accumulators and **both** rolling
checksums select the history suffix to apply and validate every destination.
Already-final files are accepted; absent files can start at an ADD. ADD does
not overwrite an unknown existing file. DELETE validates a present source; an
absent final target is accepted. `--no-checksum` applies only to the legacy
(0x0209) application path.

### Applying and inspecting 0x0320 patches

```sh
rtptool inspect patch.rtp --verbose
rtptool list patch.rtp --type modify
rtptool verify patch.rtp --programs
rtptool apply patch.rtp --source ./old-files --output ./patched-files
```

`list` expands histories into their operations. `extract` includes every
compressed child, with its payload offset in the output filename. `verify`
requires the exact expanded length, a stream terminator and sub-byte padding,
and checks ADD destinations. `--programs` also executes MODIFY programs against
a synthetic zero source to check declared bounds and count opcodes; it does not
validate content for those synthetic sources.

The 0x0320 applier writes a separate staging tree of changed files. DELETE
removes only staged output, never the source. Merge the staged changes and the
reported deletions into the base tree yourself. Application returns a failure
status if any selected record cannot be produced. Paths are looked up without
case sensitivity; traversal and symlinks are rejected for the staging-tree path.
Payload memory usage can exceed 1 GiB for large archives.

The library exposes `apply_record(&patch, &record, Option<&[u8]>)`, returning
`Result<Option<Vec<u8>>, RtpError>`; `None` represents absence/deletion.
`RtpPatch::operations()` expands HISTORY groups. `decode_record` returns a
strictly decoded ADD file or MODIFY program. Legacy `patch_file` remains
available and dispatches 0x0320 records through the strict applier.

### Tests

```sh
cargo test --offline
cargo test --offline --no-default-features
```

All tests generate their own synthetic fixtures; no proprietary patch data is
needed or included. The 0x0320 support was additionally validated end to end
against a commercial 0x0320 patch set (every compressed stream decoded, every
produced file compared byte for byte with an independent reference); that
harness lives with the project that consumes it, not in this repository.

## Build

```
cargo build --release
```

Binary: `target/release/rtptool`

---

## Commands

### `inspect` — show patch summary

```
rtptool inspect <file.rtp> [--verbose]
```

```
$ rtptool inspect update.rtp
File   : update.rtp
Version: 2.09 (0x0209)
Flags  : 0x82f4
Payload: 9447947 bytes
ExtraMd: true
Dirs   : 52
Records: 17

  MODIFY : 12
  NEW    : 5
```

`--verbose` lists every record with sizes and diff lengths.

---

### `list` — table of all file records

```
rtptool list <file.rtp> [--type modify|new|rename|delete|mkdir|all]
```

```
$ rtptool list update.rtp
type      dest_size   diff_size  filename
------------------------------------------------------------
MODIFY      1048576       24576  app.exe
MODIFY       524288       16384  renderer.dll
MODIFY        65536        1024  config.ini
NEW          131072              readme.txt
...
```

Filter to a specific record type:

```
$ rtptool list update.rtp --type new
```

---

### `apply` — apply patches (legacy examples below)

```
rtptool apply <file.rtp> --source <dir> --output <dir> [options]
```

Reads source files from `--source`, writes patched versions to `--output`. Source subdirectory structure is preserved.

```
$ rtptool apply update.rtp --source ./v1.0 --output ./v1.1

Applying 12 MODIFY patch(es):
  source : ./v1.0
  output : ./v1.1

  [OK]    engine.dll  446549 B -> 446549 B  (./v1.1/engine.dll)
  [OK]    game.exe  8500623 B -> 9447947 B  (./v1.1/game.exe)
  [SKIP]  driver.dll -- source not found: ./v1.0/driver.dll
  [SKIP]  loader.dll -- checksum mismatch (...); use --no-checksum to apply anyway

Done: 10 patched, 2 skipped, 0 errors
```

**Options:**

| Flag | Effect |
|---|---|
| `--file <name>` | Only patch files whose name contains `<name>` (case-insensitive substring) |
| `--out-file <path>` | Write single-file output to this exact path (requires `--file` to match one record) |
| `--no-checksum` | Skip source-file checksum validation |

**Patch a single file:**

```
$ rtptool apply update.rtp --source ./v1.0 --output ./v1.1 --file game.exe
```

**Patch a single file to a specific path:**

```
$ rtptool apply update.rtp \
    --source ./v1.0 \
    --output /tmp \
    --file game.exe \
    --out-file ./game_patched.exe
```

**Skip checksum** (use when source files have been modified):

```
$ rtptool apply update.rtp --source ./v1.0 --output ./v1.1 --no-checksum
```

---

### `extract` — extract compressed bodies or legacy NEW-file metadata

**Extract raw compressed diffs** (for debugging or re-use):

```
$ rtptool extract update.rtp --out ./diffs
Extracting 12 compressed diffs to ./diffs/
  game.exe -> ./diffs/game.exe.diff (6787248 B)
  engine.dll -> ./diffs/engine.dll.diff (19340 B)
  ...
```

**List NEW records** (files embedded as new, no diff data):

```
$ rtptool extract update.rtp --new-only
NEW records (3): no inline data in patch
  'readme.txt'  size=131,072 bytes
  'support.dll'  size=204,800 bytes
  ...
Metadata -> ./.new_files.txt
```

**Extract only a specific file's diff:**

```
$ rtptool extract update.rtp --out ./diffs --file engine.dll
```

---

## Error messages

| Message | Meaning |
|---|---|
| `source not found: ./v1.0/foo.dll` | Source file missing from `--source` directory |
| `checksum mismatch (expected 0x…, got 0x…)` | Source file checksum doesn't match — wrong version; pass `--no-checksum` to apply anyway |
| `bad diff magic: 0x… (want 0xB59C)` | Corrupt or truncated patch file |
| `unknown opcode 0x… at stream offset …` | Decompressed diff is corrupt |

---

## Library

Add to `Cargo.toml`:

```toml
rtptool = { path = "path/to/rtptool" }
```

```rust
use rtptool::{parse, patch_file};
use std::fs;

fn main() -> Result<(), rtptool::RtpError> {
    let data = fs::read("update.rtp")?;
    let patch = parse(data)?;

    println!("{} records", patch.records.len());

    let src = fs::read("v1.0/game.exe")?;

    for rec in patch.records.iter().filter(|r| r.has_diff()) {
        if rec.filename.contains("game.exe") {
            let patched = patch_file(&patch, rec, &src, true)?;
            fs::write("v1.1/game.exe", &patched)?;
        }
    }

    Ok(())
}
```

**API:**

```rust
// Parse a .rtp file
pub fn parse(data: Vec<u8>) -> Result<RtpPatch, RtpError>;

// Decompress and apply one MODIFY record
pub fn patch_file(
    patch: &RtpPatch,
    record: &FileRecord,
    src_data: &[u8],
    check_sum: bool,
) -> Result<Vec<u8>, RtpError>;

// 31-bit rolling checksum (w1 field in entry descriptors)
pub fn checksum_w1(data: &[u8]) -> u32;

// 30-bit rolling checksum (w2 field, used for source validation)
pub fn checksum_w2(data: &[u8]) -> u32;
```
