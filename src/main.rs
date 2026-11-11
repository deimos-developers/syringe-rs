//! `syringe-rs` entry point, translated from `SyringeEx/Main.cpp`.

// The C++ project exposes a public helper API (registers, RAII handles, PE
// getters) that the injector executable itself does not consume. Keep the
// translation faithful and silence dead-code warnings for that surface.
#![allow(dead_code)]

mod crc32;
mod find_file;
mod handle;
mod log;
mod portable_executable;
mod rebuild_instructions_tests;
mod support;
mod syringe_api;
mod syringe_debugger;

use std::ffi::{CString, c_void};

use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Globalization::{CP_UTF8, WideCharToMultiByte};
use windows_sys::Win32::System::Environment::GetCommandLineW;
use windows_sys::Win32::UI::Controls::InitCommonControls;
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MessageBoxA,
};

use crate::log::Log;
use crate::support::{
    InvalidCommandArguments, LastError, parse_command_line, printable_join, replace,
};
use crate::syringe_debugger::SyringeDebugger;

const VERSION_STRING: &str = "syringe-rs 0.1.0 (SyringeEx 0.1.0.4, based on Syringe 0.7.2.0)";

fn get_arguments() -> Vec<String> {
    let mut argc = 0i32;
    let argv_w = unsafe { CommandLineToArgvW(GetCommandLineW(), &mut argc) };

    if argv_w.is_null() || argc <= 0 {
        return Vec::new();
    }

    let mut argv = Vec::with_capacity((argc - 1) as usize);

    for i in 1..argc {
        let wide = unsafe { *argv_w.add(i as usize) };
        let len = unsafe {
            WideCharToMultiByte(
                CP_UTF8,
                0,
                wide,
                -1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };

        if len <= 0 {
            argv.push(String::new());
            continue;
        }

        let mut buffer = vec![0u8; len as usize];
        unsafe {
            WideCharToMultiByte(
                CP_UTF8,
                0,
                wide,
                -1,
                buffer.as_mut_ptr(),
                len,
                std::ptr::null(),
                std::ptr::null_mut(),
            );
        }
        buffer.truncate(len as usize - 1);
        argv.push(String::from_utf8_lossy(&buffer).into_owned());
    }

    unsafe { LocalFree(argv_w as *mut c_void) };
    argv
}

fn message_box(text: &str, caption: &str, style: u32) {
    let text = text.split('\0').next().unwrap_or("");
    let text = CString::new(text).unwrap_or_default();
    let caption = caption.split('\0').next().unwrap_or("");
    let caption = CString::new(caption).unwrap_or_default();

    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            text.as_ptr() as *const u8,
            caption.as_ptr() as *const u8,
            style,
        )
    };
}

fn report_last_error(failure: &str, error: &LastError) -> u32 {
    let message = replace(&error.message, "%1", &error.insert);
    log_line!("report_last_error", "{} ({})", message, error.error as i32);

    message_box(
        &format!("{}\n\n{}", failure, message),
        VERSION_STRING,
        MB_OK | MB_ICONERROR,
    );

    error.error
}

fn report_invalid_arguments() -> u32 {
    message_box(
        "syringe-rs cannot be run like that.\n\n\
         Usage:\nsyringe-rs.exe <exe name> [-i=<injectedfile.dll> ...] [--args=\"<arguments>\"]",
        VERSION_STRING,
        MB_OK | MB_ICONINFORMATION,
    );

    log_line!(
        "report_invalid_arguments",
        "Invalid command line arguments given, exiting..."
    );
    ERROR_INVALID_PARAMETER
}

fn run(arguments: &[String]) -> u32 {
    unsafe {
        InitCommonControls();
    }

    Log::open("syringe-rs.log");

    log_line!("run", "{}", VERSION_STRING);
    log_line!("run", "===============");
    log_line!();
    log_line!("run", "arguments = \"{}\"", printable_join(arguments));

    let mut failure = "Could not load executable.";
    let exit_code;

    let command = match parse_command_line(arguments) {
        Ok(command) => command,
        Err(InvalidCommandArguments) => {
            let code = report_invalid_arguments();
            log_line!("run", "Exiting on failure.");
            return code;
        }
    };

    log_line!(
        "run",
        "Trying to load executable file \"{}\"...",
        command.executable_name
    );
    log_line!();

    let mut debugger =
        match SyringeDebugger::new(&command.executable_name, command.syringe_arguments) {
            Ok(debugger) => debugger,
            Err(error) => {
                let code = report_last_error(failure, &error);
                log_line!("run", "Exiting on failure.");
                return code;
            }
        };

    failure = "Could not run executable.";

    log_line!("run", "find_dlls();");
    log_line!();
    debugger.find_dlls();

    log_line!("run", "run(\"{}\");", command.game_arguments);
    log_line!();

    match debugger.run(&command.game_arguments) {
        Ok(()) => {
            log_line!("run", "run finished.");
            log_line!("run", "Exiting on success.");
            return ERROR_SUCCESS;
        }
        Err(error) => {
            exit_code = report_last_error(failure, &error);
        }
    }

    let _ = failure;
    log_line!("run", "Exiting on failure.");
    exit_code
}

fn main() {
    let exit_code = run(&get_arguments());
    std::process::exit(exit_code as i32);
}
