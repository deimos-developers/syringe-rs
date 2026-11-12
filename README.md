# syringe-rs

`syringe-rs` is a Rust reimplementation of [SyringeEx](https://github.com/Phobos-developers/SyringeEx),
a 32-bit Windows DLL injector and runtime hook loader for Command & Conquer: Yuri's Revenge.

It starts a target executable under the Windows debugging API, loads one or more hook DLLs into the
new process, and installs code hooks declared by those DLLs. The command-line interface, hook file
formats, handshake protocol, feature flags, and C++ hook ABI remain compatible with SyringeEx.

The package also exposes a small host-testable library (`syringe_rs`) for the ABI, command-line
parsing, CRC32, and Win32/PE helpers. The executable is still `syringe.exe`.

## Unofficial project and EA notice

This is an unofficial community project. It is not affiliated with, endorsed by, or supported by
Electronic Arts Inc.

Command & Conquer, Yuri's Revenge, and all related names, marks, and assets are the property of
Electronic Arts Inc. or their respective owners. Electronic Arts has not endorsed and does not
support this product. Use it only with legally obtained copies of the game and in accordance with
Electronic Arts' modding guidelines.

## License

This port is distributed under the **GNU General Public License, version 3 only**
(`GPL-3.0-only`). See [`LICENSE`](LICENSE).

The original SyringeEx code is licensed under the GNU Lesser General Public License, version 3.
SyringeEx in turn is based on the original Syringe project by Patrick "pd" Dinklage, with
contributions from Jan Newger and the Ares project.

## Background

Syringe was originally written as an injector for Yuri's Revenge mods. It loads extension DLLs into
the game process, redirects selected instructions to hook functions, and provides a small API for
reading and modifying the game's registers and memory.

SyringeEx modernized that codebase, added multithreaded hook support and feature negotiation, and
kept the original hook ABI. `syringe-rs` translates that implementation to Rust while preserving the
parts that hook DLLs depend on.

## Related project

[`deimos`](../deimos) is the companion hook host: it emits the
`.syhks00`/`.syexe00` records and implements the handshake that this loader
parses. The two repositories keep independent ABI modules (`syringe_rs` here,
`deimos::syringe_api` there) so each can be tested and released on its own;
loader-visible changes must be made in both and covered by both suites.

## Requirements

- Windows x86 for running the injector and the target game.
- Rust 1.85 or newer.
- A 32-bit Windows target installed through `rustup`:
  - `i686-pc-windows-msvc` with Visual Studio Build Tools and the Windows SDK, or
  - `i686-pc-windows-gnu` with MinGW-w64.
- A C/C++ toolchain and CMake at build time. The `zydis` crate compiles its bundled C sources with
  CMake.

Cross-compiling from Linux to `i686-pc-windows-gnu` is supported.

## Building

MSVC:

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

MinGW-w64:

```bash
rustup target add i686-pc-windows-gnu
CC_i686_pc_windows_gnu=i686-w64-mingw32-gcc \
CXX_i686_pc_windows_gnu=i686-w64-mingw32-g++ \
AR_i686_pc_windows_gnu=i686-w64-mingw32-ar \
CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER=i686-w64-mingw32-gcc \
cargo build --release --target i686-pc-windows-gnu
```

The executable is written to `target/<target>/release/syringe.exe`.

## Command-line usage

### Executable selection

The first argument that does not begin with `-` is the target executable:

```text
syringe.exe game.exe
```

The injector creates the process suspended, attaches as its debugger, and resumes it after the
initial breakpoint is reached.

### Passing arguments to the target

Use `--args="..."` to pass a command line to the target:

```text
syringe.exe game.exe --args="-CD. -SPAWN"
```

The text after `--args=` is forwarded as-is.

### DLL injection

By default, `syringe-rs` scans the current directory for files matching `*.dll` and considers each
one as a hook host. A DLL is loaded only if it is recognized as compatible (see below).

To load specific DLLs, use one or more `-i=` options:

```text
syringe.exe game.exe -i=ExtensionA.dll -i=ExtensionB.dll
```

A recognized DLL with an empty hook section is still loaded, so its `DllMain` can run. This is a
small superset of the original Syringe behavior.

### Debugger lifetime

- `--detach` — detach after hook installation instead of staying attached.
- `--nodetach` — keep the debugger attached (default).
- `--nowait` — do not wait for the target process to exit.
- `--handshakes` — call `SyringeHandshake` in candidate DLLs and let them accept or reject the host.

Examples:

```text
syringe.exe game.exe --detach
syringe.exe game.exe --detach --nowait
```

## Hook DLL format

A hook DLL can declare hooks in a `.syhks00` section. The layout is the `HookDecl` structure from
`Syringe.h`:

```cpp
#include <Syringe.h>

DEFINE_HOOK(0x00401000, ExampleHook, 5)
{
    // ...
    return 0;
}
```

Each declaration contains the hook address, the number of overwritten bytes, and a preferred-image-
base pointer to the hook name. The Rust ABI types are available from `syringe_rs::syringe_api`:

```rust
use syringe_rs::syringe_api::{HookDecl, HostDecl, HOOKS_SECTION};

let hook = HookDecl::new(0x004F_4583, 6, 0x1040_0000);
let host = HostDecl::new(0, 0x1040_0010);
assert!(hook.is_named());
println!("{HOOKS_SECTION}: {hook:?} {host:?}");
```

For compatibility with older tooling, a DLL without a `.syhks00` section may instead be accompanied
by a text file named `<dllname>.inj`. Each non-comment line has the form:

```text
0x00401000 = ExampleHook, 5
```

A DLL that exports `SyringeHandshake` can inspect the host and accept or reject it. A DLL can also
provide a `.syexe00` section with `declhost` entries to restrict which executables it accepts.

## Library API

The `syringe_rs` library makes the loader's pure pieces reusable and testable without Windows:

| Module | Contents |
| --- | --- |
| `syringe_api` | `HookDecl`, `HostDecl`, `SyringeHandshakeInfo`, `HookProc`, section names, feature flags, layout assertions. |
| `support` | `CommandLine`, `parse_command_line`, `trim`, `replace`, printable helpers. |
| `crc32` | Table-driven CRC32 used by handshakes and hook checksums. |
| `debugger` | Windows-only debug loop, DLL discovery, hook installation, export resolution. |
| `portable_executable` | Windows-only 32-bit PE parser and import/section helpers. |
| `handle`, `find_file`, `log` | Windows-only RAII and platform helpers. |

Examples:

```bash
cargo run --example declarations
cargo run --example command_line -- game.exe --detach --args="-SPAWN"
```

`examples/declarations.rs` inspects the ABI types without a game; `examples/command_line.rs`
demonstrates how the loader separates its flags from game arguments.

## Feature Flags API

Feature flags let a DLL detect whether the running injector supports optional behavior. A DLL should
assume `false` for every flag and check the flag before relying on the corresponding feature.

### How it works

When a compatible DLL is loaded, `syringe-rs` looks up exported boolean variables in the
`SyringeFeatures` namespace and writes `true` into each supported flag. Older injectors leave the
variables at their default `false`.

### Using feature flags

```cpp
#include <Syringe.h>

if (SyringeFeatures::ZFPreservation)
{
    // Zero Flag preservation is available.
}
else
{
    // Fall back, or refuse to install the hook.
}
```

### Current feature flags

| Flag | Meaning |
| --- | --- |
| `ESPModification` | Hook code may change ESP across the hook boundary. |
| `ZFPreservation` | The Zero Flag is preserved after hook execution. |
| `ReladdrInstructionFixup` | Relative JMP/CALL/Jcc instructions in overwritten code are relocated into trampolines. |

All new injector capabilities beyond the original Syringe should be exposed as feature flags.

### Adding a feature flag

1. Add an exported boolean to the `SyringeFeatures` namespace in the public API header.
2. Add the symbol name to `FEATURE_FLAG_NAMES` in `src/debugger/mod.rs`.
3. Document the flag and its compatibility contract here.

## Logging

`syringe-rs` writes `syringe.log` in the current working directory. Each line has the form:

```text
[HH:MM:SS:mmm] Debug: <rust_function>: <message>
```

The log records command-line parsing, DLL discovery, PE information, hook installation, debugger
events, and the target's exit code. Output debug strings from the target are forwarded to the same
log.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/lib.rs` | Library roots and platform/feature gating. |
| `src/main.rs` | Windows entry point, command line, error reporting, log setup. |
| `src/syringe_api.rs` | C++-compatible ABI: hook/host declarations and handshake. |
| `src/debugger/mod.rs` | Debug loop, breakpoints, hook creation, loader calls. |
| `src/debugger/discovery.rs` | `.syhks00` / `.syexe00` / `.inj` parsing and handshake. |
| `src/portable_executable.rs` | 32-bit PE parser and import/section helpers. |
| `src/log.rs` | `Debug: <function>: ...` logging. |
| `src/crc32.rs` | Hook checksum used by the handshake ABI. |
| `src/handle.rs` | RAII wrappers for Win32 handles and remote memory. |
| `src/find_file.rs` | `FindFirstFileA` / `FindNextFileA` wrapper. |
| `src/support.rs` | Command-line parsing and string/error helpers. |
| `src/rebuild_instructions_tests.rs` | Tests for relative-instruction rewriting. |
| `examples/` | Host-runnable ABI and command-line examples. |
| `.github/workflows/ci.yml` | Linux formatting/lint/host tests and Windows x86 tests/build. |

## Testing

Pure modules (`syringe_api`, `support`, `crc32`) and the examples run on any host:

```bash
cargo test --all-targets
```

On the development machine this produces **14** host tests. The complete Windows x86 suite covers
the PE parser, relative-instruction rewriting, ABI sizes, command-line parsing, and CRC32; it can be
run natively on Windows:

```powershell
rustup target add i686-pc-windows-msvc
cargo test --target i686-pc-windows-msvc
```

or from Linux with Wine and the GNU target:

```bash
CARGO_TARGET_I686_PC_WINDOWS_GNU_RUNNER=wine \
cargo test --target i686-pc-windows-gnu
```

That run currently reports **36** tests.

The CI workflow runs formatting, strict clippy (`-D warnings`), and host tests on Linux, then runs
the x86 test suite and a release build on Windows. The workflow is in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Robustness notes

The translation intentionally keeps the C++ behavior where hook DLLs depend on it, but several
crash/UB paths were hardened:

- `HookDecl`/`HostDecl` are shared with the loader instead of duplicated; their 16-byte layout is
  asserted at compile time.
- `HookBuffer` no longer derives `Copy` for a type containing a map and checksum.
- `set_bp` reads the original opcode before inserting the breakpoint; `read_mem` checks the exact
  byte count.
- The PE parser rejects section counts outside `1..=96`, returns `Option` from `find_section`, stops
  `read_c_string` at EOF/NUL, and clears stale imports on re-parse.
- NUL bytes in DLL/library names no longer panic; trailing partial hook records are treated as
  padding.
- Host matching uses the executable's base name rather than the full path.
- `replace` uses standard string replacement instead of the original parser's pathological loop.

## Compatibility and limitations

- 32-bit only. The injector, target process, and hook DLLs must all be x86.
- Windows is required at runtime. Cross-compilation from Linux is supported for the GNU target.
- The PE parser follows the original 32-bit parser; malformed or unsupported executables are rejected
  instead of being partially loaded.
- The loader does not verify the target executable against a known checksum. Hook addresses remain
  the responsibility of the hook DLL.
