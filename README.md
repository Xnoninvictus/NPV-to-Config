# NPVS to Config Converter

A single-file Python utility that scans a directory for `*.npvs` and `*.npvt` files, extracts every proxy configuration inside them, and converts each one to a standard, shareable proxy URI (`vmess://`, `vless://`, `trojan://`, `ss://`, `hysteria2://`, etc.). All results are written to a single `.txt` file — one URI per line — ready to paste into any client like v2rayN, NekoBox, Hiddify, Shadowrocket, or sing-box.

This README covers how the code works, how to run it, and how to package it as a standalone executable for Windows, macOS, or Linux.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Supported Protocols](#supported-protocols)
3. [How It Works](#how-it-works)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Input Formats](#input-formats)
8. [Output Format](#output-format)
9. [Code Walkthrough](#code-walkthrough)
10. [Building a Standalone Executable](#building-a-standalone-executable)
11. [Troubleshooting](#troubleshooting)
12. [Known Limitations](#known-limitations)
13. [Extending the Converter](#extending-the-converter)
14. [License](#license)

---

## What It Does

- **Scans a directory** for `.npvs` and `.npvt` files (recursively? — no, top-level only; see [Usage](#usage)).
- **Decodes each config** — both the base64-encoded profile fields (`npvs1:...`) and the outer file wrapper.
- **Converts to standard URIs** — normalizes the internal representation into the exact URI format each proxy client expects.
- **Writes a single flat file** — `converted_configs.txt`, one URI per line, no formatting, ready to import.
- **Reports warnings/errors** at the end — unsupported config types, malformed entries, or files that fail to load.

The script is **pure Python 3** — standard library only. No `pip install` required.

---

## Supported Protocols

The script maps v2rayN's internal `EConfigType` numeric IDs to URI schemes:

| `configType` | Protocol | URI scheme |
|--------------|----------|------------|
| `1`  | VMess        | `vmess://` (base64 JSON) |
| `3`  | Shadowsocks  | `ss://` (base64 userinfo) |
| `4`  | SOCKS        | `socks://` |
| `5`  | VLESS        | `vless://` |
| `6`  | Trojan       | `trojan://` |
| `7`  | Hysteria2    | `hysteria2://` |
| `8`  | TUIC         | `tuic://` |
| `9`  | WireGuard    | `wireguard://` |
| `10` | HTTP(S)      | `http://` |
| `11` | AnyTLS       | `anytls://` |
| `12` | Naive        | `naive+https://` |

If `configType` is missing or unrecognized, the script attempts **fallback inference** based on which fields are present (e.g. `flow` + `publicKey` → VLESS; `method` → Shadowsocks; `obfsPassword` → Hysteria2; etc.).

---

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  1. SCAN                                                     │
│     Walk the target directory, collect all *.npvs and        │
│     *.npvt files, sorted and de-duplicated.                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  2. LOAD                                                     │
│     .npvs → JSON (with optional "NPV" header line stripped). │
│     .npvt → custom line format: <b64_name>,<b64_json>,       │
│             best-effort parsed line by line.                 │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  3. DECODE                                                   │
│     Every field value starting with "npvs1:" is base64-      │
│     decoded back to plaintext (server address, password,     │
│     UUID, SNI, etc.).                                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  4. CONVERT                                                  │
│     Dispatch by configType → protocol-specific URI builder.  │
│     Fall back to inference if configType is absent.          │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  5. WRITE                                                    │
│     Append each URI to a list; at the end, dump all to       │
│     converted_configs.txt (UTF-8, one per line).             │
│     Print a summary and any warnings to stderr.              │
└──────────────────────────────────────────────────────────────┘
```

---

## Requirements

- **Python 3.7+** (uses f-strings and `pathlib`; tested on 3.9–3.12).
- **No third-party packages.** Everything used (`base64`, `json`, `sys`, `pathlib`, `urllib.parse`) ships with Python.

---

## Installation

### Option 1 — Just run it (recommended)

1. Save the file as `npvs_converter_full.py`.
2. That's it. No install step.

### Option 2 — Clone into a project

```bash
git clone <your-repo-url>
cd <your-repo>
python3 npvs_converter_full.py --help
```

### Option 3 — Install as a script on your `PATH` (Linux/macOS)

```bash
chmod +x npvs_converter_full.py
sudo cp npvs_converter_full.py /usr/local/bin/npvs-convert
npvs-convert ~/configs
```

---

## Usage

### Basic

```bash
python3 npvs_converter_full.py <input_directory>
```

This scans `<input_directory>` for `.npvs` / `.npvt` files and writes `converted_configs.txt` **in the current working directory**.

### Custom output path

```bash
python3 npvs_converter_full.py ~/Downloads/npv_files ~/Desktop/all-configs.txt
```

### Run with no arguments

```bash
python3 npvs_converter_full.py
```

Defaults to scanning the **current directory** and writing `converted_configs.txt` there.

### Example session

```bash
$ python3 npvs_converter_full.py ./my_configs ./output.txt
Scanned 3 file(s) in /home/user/my_configs
  (.npvs: 2, .npvt: 1)
Converted 47 config(s)
Output written to: /home/user/output.txt

Warnings/Errors:
  - backup.npvs: error converting "Old Node" — missing 'password' field
  - broken.npvt: failed to load — Expecting value: line 1 column 1 (char 0)
```

### Command-line arguments

| Position | Argument | Default | Description |
|----------|----------|---------|-------------|
| 1 | `input_directory` | `.` (CWD) | Directory containing the `.npvs` / `.npvt` files. |
| 2 | `output_file` | `converted_configs.txt` | Path of the output text file. Overwritten each run. |

---

## Input Formats

### `.npvs` — NekoBox / v2rayN "share" file

A UTF-8 JSON file, usually with an `NPV` header line on top:

```
NPVS
{
  "configs": [
    { "name": "Tokyo-01", "v2rayProfile": { "configType": 5, "server": "npvs1:MTIzLg==", ... } },
    { "name": "Frankfurt",  "v2rayProfile": { ... } }
  ]
}
```

- The first line is stripped if it starts with `NPV`.
- File is read with `utf-8-sig` so a byte-order mark is tolerated.
- Each field that begins with `npvs1:` is base64-decoded by `npvs_decode()`.

### `.npvt` — line-based template file

Each non-empty line is `<base64_name>,<base64_json>`:

```
VG9reW8tMDE=,eyJjb25maWdUeXBlIjo1LCJzZXJ2ZXIiOiIxLjIuMy40Iiwic2VydmVyUG9ydCI6NDQzfQ==
```

- Line 1 may be an `NPVT` header (stripped).
- Name is base64-decoded to UTF-8 (or kept as-is on failure).
- Payload is base64-decoded, parsed as JSON, and treated as a `v2rayProfile`.
- Lines that fail any step are silently skipped.

---

## Output Format

A plain UTF-8 text file with one URI per line:

```
vmess://eyJ2IjoiMiIsInBzIjoiVG9reW8tMDEiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiLi4uIn0=
vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&type=ws&security=tls&sni=example.com#Node%20Name
trojan://mypassword@example.com:443?security=tls&type=tcp&sni=example.com#Trojan%20Node
hysteria2://userpass@example.com:443/?sni=example.com&insecure=1#Hy2%20Server
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#SS%20Node
```

- Lines starting with `#` are **errors**, not usable configs (e.g. `# unsupported configType=99 name=foo`). Filter them out before importing.
- The file is **overwritten** each run.
- UTF-8, no BOM, LF line endings.

---

## Code Walkthrough

### Base64 / decoding helpers

- **`b64_pad(s)`** — adds `=` padding to a base64 string (Instagram/NekoBox often strip it).
- **`npvs_decode(value)`** — detects the `npvs1:` prefix and decodes the rest as base64 UTF-8. Non-prefixed values pass through unchanged.
- **`decode_profile(profile)`** — applies `npvs_decode` to every value in a profile dict.
- **`fix_mojibake(s)`** — repairs strings that were decoded as Latin-1 when they were really UTF-8 (a common artifact of base64 pipelines).

### Common extraction helpers

- **`get_host_port(item, p)`** — prefers `p["server"]` + `p["serverPort"]`; falls back to splitting `item["address"]` on the last `:`.
- **`qs(params)`** — URL-encodes a dict, dropping empty/zero/False values so URIs stay clean.
- **`get_remark(item)`** — returns the URL-encoded node name (with mojibake fixed).

### URI builders

One function per protocol (`to_vmess`, `to_ss`, `to_socks`, `to_vless`, `to_trojan`, `to_hy2`, `to_tuic`, `to_wireguard`, `to_http`, `to_anytls`, `to_naive`). Each:

1. Pulls host/port and credentials from the profile.
2. Builds a protocol-specific parameter dict.
3. Assembles the URI string.

### Dispatcher — `convert_item(item)`

- Looks up `configType` in a dict of `{id: builder}`.
- If not found, runs a chain of heuristics based on which fields are present.
- Returns either a valid URI **or** a `# comment` string describing why it failed.

### Loaders

- **`load_npvs(path)`** — JSON parse (with NPV header stripping).
- **`load_npvt(path)`** — best-effort line parser.
- **`load_configs(path)`** — dispatches on file extension.

### Entry point — `main()`

Reads CLI args, scans, converts, writes output, prints a summary, and lists warnings.

---

## Building a Standalone Executable

If you want to hand this to someone without Python installed, package it with **PyInstaller**. The result is a single binary that runs on a machine with no Python.

### 1. Install PyInstaller

```bash
pip install pyinstaller
```

### 2. Build a one-file executable

```bash
pyinstaller --onefile --name npvs-convert npvs_converter_full.py
```

Output lands in `dist/npvs-convert` (Linux/macOS) or `dist\npvs-convert.exe` (Windows).

### 3. Verify

```bash
./dist/npvs-convert ./my_configs ./output.txt
```

### Reducing binary size

```bash
pyinstaller --onefile --strip --upx-dir=/path/to/upx \
            --name npvs-convert npvs_converter_full.py
```

- `--strip` removes symbols (Linux/macOS only).
- `--upx-dir` compresses with [UPX](https://upx.github.io/) — typically cuts 40–60%.
- `--exclude-module` for anything unused (there's nothing heavy here, so gains are limited).

A bare build of this script is usually **~7–10 MB** on Windows, **~6–9 MB** on macOS, **~5–8 MB** on Linux.

### Cross-platform builds

PyInstaller does **not** cross-compile. You must run it on each target OS:

| Target | Build on |
|--------|----------|
| Windows `.exe` | Windows |
| macOS binary | macOS |
| Linux binary | Linux |

Alternatives:

- **Nuitka** — often produces faster, smaller binaries:
  ```bash
  pip install nuitka
  python -m nuitka --onefile --standalone npvs_converter_full.py
  ```
- **cx_Freeze** — heavier, but battle-tested.
- **Docker / GitHub Actions** — spin up Windows, macOS, and Linux runners in a matrix build to produce all three artifacts from one repo push.

### Adding an icon and version metadata (Windows)

```bash
pyinstaller --onefile --name npvs-convert ^
            --icon=icon.ico ^
            --version-file=version.txt ^
            npvs_converter_full.py
```

Example `version.txt`:

```
VSVersionInfo(
  ffi=FixedFileInfo(filevers=(1,0,0,0), prodvers=(1,0,0,0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('FileDescription', 'NPVS Config Converter'),
      StringStruct('FileVersion', '1.0.0.0'),
      StringStruct('ProductName', 'NPVS Config Converter'),
    ])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
```

### Drag-and-drop wrapper (optional)

If you want a `.bat` (Windows) or `.command` (macOS) shim so users can drop a folder onto the executable, create a small launcher script. Example Windows `convert.bat`:

```bat
@echo off
npvs-convert.exe %~dp0 %~dp0\converted_configs.txt
pause
```

---

## Troubleshooting

| Symptom | Cause & fix |
|---------|-------------|
| **`No .npvs or .npvt files found`** | The script only scans the **top level** of the given directory. Move files there or run per-subfolder. |
| **`is not a directory`** | First argument must be an existing folder, not a file. |
| **All URIs prefixed with `#`** | Your file uses a config type that isn't in the map and inference failed. See [Extending the Converter](#extending-the-converter). |
| **`Expecting value: line 1 column 1` on load** | The `.npvs` file isn't valid JSON after header stripping — perhaps it's encrypted, corrupted, or actually an `.npvt`. |
| **Node names show as `????` or garbage** | Mojibake. `fix_mojibake()` handles the common case; if your file is double-encoded, pre-process with `iconv -f latin1 -t utf8`. |
| **Passwords with special characters break the URI** | Builders already `quote()` userinfo; if a client still fails, the password may contain a null byte or control character. |
| **Empty output file** | The file loaded fine but contained zero `configs`. Check that the JSON key is `configs`, not something else. |
| **`.npvt` file yields nothing** | The line format is best-effort; payloads must be valid base64 JSON. Check with `base64 -d` manually. |

Run with the output file as `/dev/stdout` to preview URIs without writing a file:

```bash
python3 npvs_converter_full.py ./configs /dev/stdout
```

---

## Known Limitations

- **Non-recursive scan.** Only `*.npvs` / `*.npvt` directly inside the target directory are picked up.
- **`.npvt` format is guessed.** The line-based decoder is heuristic; unusual variants will produce no output rather than an error.
- **No v2rayN `configType` 2** (`ShadowsocksR`) — SS-R is deprecated and omitted.
- **No subscription export.** Output is a flat URI list, not a v2rayN subscription file.
- **No de-duplication.** If the same node appears in two files, both URIs are written.
- **No config validation.** A malformed profile may yield a URI that a client rejects; you'll find out on import.
- **Fallback inference is best-effort.** Ambiguous profiles (e.g. with both `uuid` and `password`) may be misclassified.
- **No interactive mode.** Command-line only.

---

## Extending the Converter

### Adding a new protocol

1. Write a `to_<name>(item, p)` function that returns a URI string.
2. Register it in the `converters` dict inside `convert_item()`:

    ```python
    converters = {
        1: to_vmess,
        ...
        13: to_my_new_protocol,   # <- add here
    }
    ```

3. (Optional) Add a branch to the inference chain at the bottom of `convert_item()`.

### Adding a new input format

Extend `load_configs()`:

```python
if suffix == ".npvx":
    return load_npvx(path)
```

Return a list of dicts shaped like `{"name": ..., "v2rayProfile": {...}}`.

### Adding recursive scan

Replace the body of `find_npvs_files()`:

```python
def find_npvs_files(directory: Path):
    files = []
    for pattern in NPX_EXTENSIONS:
        files.extend(directory.rglob(pattern))  # rglob = recursive
    return sorted(set(files))
```

---

## License

MIT License. Use, modify, and redistribute freely. See `LICENSE` for details.

---

## Contributing

Pull requests welcome for:

- Additional `configType` IDs (ShadowsocksR, Juicity, etc.).
- Recursive scanning as a CLI flag (`--recursive`).
- De-duplication of identical URIs.
- Optional JSON output alongside the URI list.
- Unit tests for each URI builder.

Please include a sample input file (with fake credentials) for any new protocol so reviewers can verify the output.
