# Juliet Test Suite (C): Download, Build, and Strip Binaries

This document describes how to:

1. Download `arichardson/juliet-test-suite-c` from GitHub  
2. Build the C/C++ Juliet test cases into individual executables  
3. Strip symbols from the generated binaries

---

## 1. Prerequisites

You need a Unix-like environment (e.g. Linux, macOS) with:

- **Git**
- **Python 3**
- **CMake**
- **make**
- A C/C++ compiler (e.g. `gcc`, `g++` or `clang`, `clang++`)
- `strip` from GNU binutils (usually already available on Linux)

On Debian/Ubuntu, for example:

```bash
sudo apt-get update
sudo apt-get install -y   git python3 cmake build-essential binutils
```

---

## 2. Clone the Repository

```bash
# Choose a directory where you want to keep the sources
cd /path/to/where/you/want/the/repo

# Clone the Juliet C/C++ test suite with Unix build system
git clone https://github.com/arichardson/juliet-test-suite-c.git

cd juliet-test-suite-c
```

The repository contains:

- `testcases/` – test case sources organized by CWE  
- `CMakeLists.txt` – CMake build configuration  
- `juliet.py` – main driver script to generate and build the test cases  
- `juliet-run.sh` – runner script for executing tests  
- `bin/` – output directory (created after the first build) where binaries are placed by CWE and “good”/“bad” variants.

---

## 3. Building the Test Cases

The `juliet.py` script orchestrates:

- Copying `CMakeLists.txt` into each CWE directory
- Running `cmake` to generate Makefiles
- Running `make` to build the binaries  

It supports options to **clean**, **generate**, **make**, and **run** test cases for selected CWEs or for all CWEs.

### 3.1 Build all CWEs

From the repository root:

```bash
cd /path/to/juliet-test-suite-c

# Generate build files and compile all CWEs
python3 juliet.py -g -m -a
```

Explanation of the options:

- `-g` / `--generate` – run CMake to generate Makefiles  
- `-m` / `--make` – invoke `make` to build  
- `-a` / `--all` – target **all** CWEs  

After this, the default output hierarchy is:

```text
bin/
  CWE121/
    good/
      CWE121_..._good
      ...
    bad/
      CWE121_..._bad
      ...
  CWE122/
    good/
    bad/
  ...
```

Each CWE has a `bin/CWEXXX` directory, split into `good` and `bad` subdirectories containing the “safe” and “vulnerable” binaries respectively.

### 3.2 Build specific CWEs only (optional)

If you only want a subset of CWEs, list the CWE numbers instead of using `-a`. For example, to build only CWE 121 and 122:

```bash
cd /path/to/juliet-test-suite-c

python3 juliet.py -g -m 121 122
```

This will generate and build binaries only for the specified CWE directories.

---

## 4. Stripping Symbols from the Built Binaries

Once the binaries are built under `bin/`, you can strip their symbols using `strip`. Stripping reduces file size and removes symbol information (useful for some benchmarking or deployment scenarios).

> **Warning**: Stripping removes debugging information and symbol names. Only do this on binaries where you no longer need debuggability.

### 4.1 Strip all binaries under `bin/`

From the repository root:

```bash
cd /path/to/juliet-test-suite-c

# Strip all regular files in bin/ (recursively)
find bin -type f -executable -print0 | xargs -0 strip
```

This command:

1. Uses `find` to locate all executable files under `bin/`
2. Passes them to `strip` via `xargs`

If you prefer to be a bit more conservative (e.g. only strip files that look like ELF binaries on Linux), you could first inspect some files with `file bin/CWE*/good/*`.

### 4.2 Strip “good” and “bad” binaries separately (optional)

If you want explicit control over “good” and “bad” binaries:

```bash
cd /path/to/juliet-test-suite-c

# Strip "good" binaries
find bin -type f -path '*good/*' -print0 | xargs -0 strip

# Strip "bad" binaries
find bin -type f -path '*bad/*' -print0 | xargs -0 strip
```

---

## 5. Full Example Script

Below is a complete example that:

1. Clones the repository  
2. Builds **all CWEs**  
3. Strips all generated binaries  

Save it as `build_and_strip_juliet.sh` if you want to re-use it.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Configuration
JULIET_DIR="${PWD}/juliet-test-suite-c"
REPO_URL="https://github.com/arichardson/juliet-test-suite-c.git"

# 2. Clone if necessary
if [ ! -d "${JULIET_DIR}" ]; then
  echo "[*] Cloning Juliet test suite from ${REPO_URL}"
  git clone "${REPO_URL}" "${JULIET_DIR}"
else
  echo "[*] Using existing repository at ${JULIET_DIR}"
fi

cd "${JULIET_DIR}"

# 3. Build all CWEs (generate + make)
echo "[*] Building all CWEs (this may take a while)..."
python3 juliet.py -g -m -a

# 4. Strip binaries
if [ -d "bin" ]; then
  echo "[*] Stripping binaries under bin/..."
  find bin -type f -executable -print0 | xargs -0 strip
  echo "[*] Done stripping binaries."
else
  echo "[!] bin/ directory not found – did the build succeed?"
fi
```

Make it executable and run:

```bash
chmod +x build_and_strip_juliet.sh
./build_and_strip_juliet.sh
```

---

## 6. Cleaning and Rebuilding (Optional)

If you want to clean generated build files and rebuild:

```bash
cd /path/to/juliet-test-suite-c

# Clean CMake/Make files for all CWEs
python3 juliet.py -c -a

# Regenerate and rebuild all CWEs
python3 juliet.py -g -m -a
```

Here:

- `-c` / `--clean` instructs `juliet.py` to remove CMake and build artifacts before regenerating.

You can then repeat the stripping step from Section 4 if needed.
