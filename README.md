# syringe-rs

`syringe-rs` is a Rust reimplementation of [SyringeEx](https://github.com/Phobos-developers/SyringeEx),
a 32-bit Windows DLL injector and runtime hook loader for Command & Conquer: Yuri's Revenge.

It starts a target executable under the Windows debugging API, loads one or more hook DLLs into the
new process, and installs code hooks declared by those DLLs. The command-line interface, hook file
formats, handshake protocol, feature flags, and C++ hook ABI are kept compatible with SyringeEx.

The Cargo package is named `syringe-rs`; the executable it produces is `syringe.exe`.

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

Each declaration contains the hook address, the number of overwritten bytes, and a pointer to the
hook name.

For compatibility with older tooling, a DLL without a `.syhks00` section may instead be accompanied
by a text file named `<dllname>.inj`. Each non-comment line has the form:

```text
0x00401000 = ExampleHook, 5
```

A DLL that exports `SyringeHandshake` can inspect the host and accept or reject it. A DLL can also
provide a `.syexe00` section with `declhost` entries to restrict which executables it accepts.

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
2. Add the symbol name to the feature flag list in `src/syringe_debugger.rs`.
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
| `src/main.rs` | Entry point, command line, error reporting, log setup. |
| `src/syringe_debugger.rs` | Debug loop, DLL scanning, hook installation, loader and export resolution. |
| `src/portable_executable.rs` | 32-bit PE parser and import/section helpers. |
| `src/syringe_api.rs` | C++-compatible register, hook, host, and handshake declarations. |
| `src/log.rs` | `Debug: <function>: ...` logging. |
| `src/crc32.rs` | Hook checksum used by the handshake ABI. |
| `src/handle.rs` | RAII wrappers for Win32 handles and remote memory. |
| `src/find_file.rs` | `FindFirstFileA` / `FindNextFileA` wrapper. |
| `src/support.rs` | Command-line parsing and string/error helpers. |
| `src/rebuild_instructions_tests.rs` | Tests for relative-instruction rewriting. |

## Testing

The hook-rewrite and PE parser tests can run on a Linux host with Wine and the GNU target:

```bash
CARGO_TARGET_I686_PC_WINDOWS_GNU_RUNNER=wine \
cargo test --target i686-pc-windows-gnu
```

On Windows, omit the runner variable. The suite covers self-PE parsing, short and near branch
rewriting, intra-trampoline targets, LOOP/JECXZ handling, and malformed-input guards.

## Compatibility and limitations

- 32-bit only. The injector, target process, and hook DLLs must all be x86.
- Windows is required at runtime. Cross-compilation from Linux is supported for the GNU target.
- The PE parser follows the original 32-bit parser and rejects truncated input instead of silently
  continuing.
- Hook installation writes to remote process memory. A failed patch can leave the target partially
  modified; rollback is not attempted, matching SyringeEx.
- `SyringeHandshake` receives a 0x100-byte message buffer; host DLLs must respect `cchMessage`.
- The traditional `Syringe.h` C++ header is still the reference API for hook DLLs. The Rust-side
  mirror exists for tests and documentation.

## Credits

- Original Syringe: Patrick "pd" Dinklage, with work by Jan Newger and the Ares project.
- SyringeEx: the Phobos developers and contributors.
- Zydis: the Zydis project and contributors.
- `syringe-rs`: the deimos-developers contributors.

## Legal

This project is an unofficial community effort and is not affiliated with Electronic Arts Inc.
Command & Conquer and Yuri's Revenge are trademarks of Electronic Arts Inc. Electronic Arts has not
endorsed and does not support this product.
