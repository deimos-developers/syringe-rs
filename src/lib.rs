//! Shared library for the `syringe` loader binary.
//!
//! The public API is split by concern:
//! - [`syringe_api`]: the Syringe host ABI (hook/host declarations, handshake).
//! - [`support`]: command-line parsing and error formatting.
//! - [`crc32`]: the CRC32 implementation used for handshakes and hook buffers.
//!
//! The debugger, PE parser and Win32 helpers are Windows-only and are gated so
//! the pure modules can be unit-tested on any host.

#![allow(dead_code)] // The translated helper API intentionally mirrors SyringeEx.

pub mod crc32;
pub mod support;
pub mod syringe_api;

#[cfg(windows)]
pub mod debugger;
#[cfg(windows)]
mod find_file;
#[cfg(windows)]
mod handle;
#[cfg(windows)]
pub mod log;
#[cfg(windows)]
mod portable_executable;

#[cfg(all(test, windows))]
mod rebuild_instructions_tests;
