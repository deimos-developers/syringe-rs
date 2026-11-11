# syringe-rs

A Rust port of [SyringeEx](https://github.com/Phobos-developers/SyringeEx), a 32-bit Windows DLL
injector and runtime hook loader. It launches a target executable under the Windows debugging API,
loads one or more hook DLLs into the target, and rewrites hook sites with generated trampolines.

The port keeps the original command-line interface, PE/hook-file formats, and the C++ hook ABI used
by SyringeEx hook DLLs.

## Features

- 32-bit Windows target process debugging via `WaitForDebugEvent` / `ContinueDebugEvent`.
- DLL injection through remote `LoadLibraryA` / `GetProcAddress` calls.
- Code hooks declared with `.syhks00` link sections or legacy `.inj` files.
- Host DLL handshake support (`.syexe00` / `SyringeHandshake`) via `--handshakes`.
- Relative-instruction fixup with Zydis: short branches, jumps, and calls are re-encoded as near
  branches when copied into a trampoline.
- Feature flags exported to hook DLLs:
  - `ESPModification`
  - `ZFPreservation`
  - `ReladdrInstructionFixup`
- C++-compatible register and hook ABI in `src/syringe_api.rs`.

## Requirements

- Rust 1.85 or newer.
- A 32-bit Windows target:
  - MSVC: `i686-pc-windows-msvc`, plus Visual Studio Build Tools and the Windows SDK.
  - MinGW-w64: `i686-pc-windows-gnu`, plus `i686-w64-mingw32-gcc`, `i686-w64-mingw32-g++`, and
    CMake.
- The `zydis` crate builds its bundled Zydis C sources with CMake, so a working C/C++ toolchain is
  required at build time.

## Build

MSVC:

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

MinGW-w64 (cross-compiling from Linux is supported):

```bash
rustup target add i686-pc-windows-gnu
CC_i686_pc_windows_gnu=i686-w64-mingw32-gcc \
CXX_i686_pc_windows_gnu=i686-w64-mingw32-g++ \
AR_i686_pc_windows_gnu=i686-w64-mingw32-ar \
CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER=i686-w64-mingw32-gcc \
cargo build --release --target i686-pc-windows-gnu
```

The executable is written to
`target/<target>/release/syringe-rs.exe`. The release profile enables fat LTO, one codegen unit,
and `opt-level = 3`.

## Usage

The first argument that does not start with `-` is the target executable:

```text
syringe-rs.exe game.exe
```

Pass arguments to the target with `--args="..."`:

```text
syringe-rs.exe game.exe --args="-CD. -SPAWN"
```

By default, every compatible DLL matching `*.dll` in the current directory is considered. To load
only selected DLLs, use one or more `-i=` options:

```text
syringe-rs.exe game.exe -i=ExtensionA.dll -i=ExtensionB.dll
```

Debugger lifetime flags:

- `--detach` — detach once all hooks have been placed.
- `--nodetach` — keep the debugger attached (default).
- `--nowait` — do not wait for the target process to exit.
- `--handshakes` — call `SyringeHandshake` in candidate DLLs before loading them.

Examples:

```text
syringe-rs.exe game.exe
syringe-rs.exe game.exe --detach
syringe-rs.exe game.exe --detach --nowait
```

The injector writes a UTF-8 log named `syringe-rs.log` in the current directory. Every line has the
form:

```text
[HH:MM:SS:mmm] Debug: <rust_function>: <message>
```

## Hook DLLs

Hook DLLs use the SyringeEx ABI. The C++ API header remains in the SyringeEx tree
(`SyringeEx/include/Syringe.h`); the Rust-side layout and register helpers are mirrored in
`src/syringe_api.rs`.

Hooks can be declared in a `.syhks00` section:

```cpp
#include <Syringe.h>

DEFINE_HOOK(0x00401000, ExampleHook, 5)
{
    // ...
    return 0;
}
```

or listed in a legacy `<dllname>.inj` file:

```text
0x00401000 = ExampleHook, 5
```

A hook DLL that exports `SyringeHandshake` can accept or reject a target. A DLL that wants to accept
only specific hosts can provide a `.syexe00` section with `declhost` entries.

## Feature Flags

When a DLL is loaded, `syringe-rs` resolves exported booleans from the `SyringeFeatures` namespace
and writes `true` into the ones it supports. Hook DLLs should default these flags to `false` and
check them before using optional behavior.

| Flag | Meaning |
| --- | --- |
| `ESPModification` | Hooks may change ESP across the hook boundary. |
| `ZFPreservation` | ZF is preserved across hook execution. |
| `ReladdrInstructionFixup` | Relative JMP/CALL/Jcc instructions in overwritten code are relocated. |

## Project Layout

| Path | Purpose |
| --- | --- |
| `src/main.rs` | Entry point, command line, error reporting, `syringe-rs.log` setup. |
| `src/syringe_debugger.rs` | Debug loop, DLL scanning, hook installation, loader/export resolution. |
| `src/portable_executable.rs` | PE32 parser and import/export/section helpers. |
| `src/syringe_api.rs` | C++-compatible register, hook, host, and handshake declarations. |
| `src/log.rs` | `Debug: <function>: ...` logging. |
| `src/crc32.rs` | Hook-buffer checksum used by the handshake ABI. |
| `src/handle.rs` | RAII wrappers for Win32 handles and remote memory. |
| `src/find_file.rs` | `FindFirstFileA` / `FindNextFileA` wrapper. |
| `src/support.rs` | Command-line parsing, message formatting, path/string helpers. |
| `src/rebuild_instructions_tests.rs` | Round-trip tests for relative-instruction rewriting. |

## Tests

The hook-rewrite tests can run on a Linux host with Wine and the GNU target:

```bash
CARGO_TARGET_I686_PC_WINDOWS_GNU_RUNNER=wine \
cargo test --target i686-pc-windows-gnu
```

On Windows, run the same command without the runner variable. The suite covers 24 cases, including
self-PE parsing, short/near branch rewriting, intra-trampoline targets, LOOP/JECXZ handling, and
malformed-input guards.

## Performance Notes

Compared with a direct line-by-line translation:

- `PortableExecutable` keeps one open `File` handle for the lifetime of the parser instead of
  reopening the executable for every import-name and thunk read.
- Logging builds the timestamp once per line, takes the logger mutex once, and writes the timestamp,
  message, and newline with three `fwrite` calls instead of one `fputc` per character.
- Release builds use fat LTO and a single codegen unit.

## Compatibility and Limitations

- 32-bit only. The target process, hook DLLs, and injector must all be x86.
- Windows only at runtime. Cross-compilation from Linux is supported for the GNU target.
- The PE parser intentionally follows the original 32-bit parser and rejects truncated/malformed
  input rather than silently continuing.
- Hook installation modifies remote process memory. Failed patches can leave the target partially
  modified; the injector does not attempt rollback, matching SyringeEx.
- `SyringeHandshake` is called with a 0x100-byte message buffer; host DLLs must respect
  `cchMessage`.

## License

The Rust port is licensed under **LGPL-3.0-only**, matching SyringeEx. See [`LICENSE`](LICENSE).

Syringe was originally created by **Patrick "pd" Dinklage**, based in part on work by **Jan Newger**,
and later maintained by contributors from the **Ares** project. SyringeEx extended and modernized
that codebase. Zydis is licensed under the MIT License.
