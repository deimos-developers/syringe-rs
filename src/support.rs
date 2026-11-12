//! Translation of `SyringeEx/Support.h`.

#[cfg(windows)]
use std::ffi::{CStr, c_void};
use std::fmt;
#[cfg(windows)]
use std::ptr::null_mut;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError, LocalFree};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    FormatMessageA,
};

pub fn trim(input: &str) -> &str {
    let Some(first) = input.find(|c| c != ' ') else {
        return input;
    };
    let last = input.rfind(|c| c != ' ').unwrap();
    &input[first..=last]
}

#[derive(Debug)]
pub struct CommandLine {
    pub syringe_arguments: Vec<String>,
    pub executable_name: String,
    pub game_arguments: String,
}

#[derive(Debug, Clone)]
pub struct InvalidCommandArguments;

impl fmt::Display for InvalidCommandArguments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid command line arguments")
    }
}

impl std::error::Error for InvalidCommandArguments {}

pub fn parse_command_line(args: &[String]) -> Result<CommandLine, InvalidCommandArguments> {
    let mut result = CommandLine {
        syringe_arguments: Vec::new(),
        executable_name: String::new(),
        game_arguments: String::new(),
    };

    let mut found_executable = false;

    for arg in args {
        if !arg.starts_with('-') && !found_executable {
            result.executable_name = arg.clone();
            found_executable = true;
        } else if let Some(rest) = arg.strip_prefix("--args=") {
            result.game_arguments = rest.to_string();
        } else {
            result.syringe_arguments.push(arg.clone());
        }
    }

    if args.is_empty() || !found_executable || result.executable_name.is_empty() {
        return Err(InvalidCommandArguments);
    }

    Ok(result)
}

pub fn replace(string: &str, pattern: &str, substitute: &str) -> String {
    if pattern.is_empty() {
        return string.to_string();
    }
    string.replace(pattern, substitute)
}

pub fn printable(data: &[u8]) -> (usize, *const u8) {
    (data.len(), data.as_ptr())
}

pub fn printable_join(arguments: &[String]) -> String {
    arguments.join(" ")
}

#[cfg(windows)]
pub fn get_format_message(error_code: u32) -> String {
    let mut buffer: *mut u8 = null_mut();

    let result = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            error_code,
            0x0400,
            &mut buffer as *mut *mut u8 as *mut u8,
            0,
            std::ptr::null(),
        )
    };

    if result == 0 || buffer.is_null() {
        // C++ leaves the returned std::string empty when FormatMessage fails.
        return String::new();
    }

    let message = unsafe {
        let text = CStr::from_ptr(buffer as *const i8)
            .to_string_lossy()
            .into_owned();
        LocalFree(buffer as *mut c_void);
        text
    };

    message
        .trim_end_matches(|c: char| c.is_whitespace())
        .to_string()
}

#[cfg(windows)]
pub struct LastError {
    pub error: u32,
    pub message: String,
    pub insert: String,
}

#[cfg(windows)]
impl LastError {
    pub fn new(error: u32) -> Self {
        Self {
            error,
            message: get_format_message(error),
            insert: String::new(),
        }
    }
}

#[cfg(windows)]
impl fmt::Debug for LastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LastError")
            .field("error", &self.error)
            .field("message", &self.message)
            .field("insert", &self.insert)
            .finish()
    }
}

#[cfg(windows)]
impl fmt::Display for LastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.error)
    }
}

#[cfg(windows)]
impl std::error::Error for LastError {}

#[cfg(windows)]
pub fn throw_lasterror(code: u32, insert: String) -> LastError {
    LastError {
        error: code,
        message: get_format_message(code),
        insert,
    }
}

#[cfg(windows)]
pub fn throw_lasterror_or(alternative: u32, insert: String) -> LastError {
    let mut code = unsafe { GetLastError() };

    if code == 0 {
        code = alternative;
    }

    LastError {
        error: code,
        message: get_format_message(code),
        insert,
    }
}

// Keep an otherwise-unused import anchored to the same translation unit, as the
// C++ header pulls in the Windows error namespace.
#[cfg(windows)]
pub const INVALID_PARAMETER: u32 = ERROR_INVALID_PARAMETER;

// Mirrors C++ stack structs that are zero-initialized before use.
#[cfg(windows)]
pub fn zeroed<T>() -> T {
    unsafe { std::mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_removes_only_outer_spaces() {
        assert_eq!(trim("  abc  "), "abc");
        assert_eq!(trim("\t abc \n"), "\t abc \n");
        assert_eq!(trim("   "), "   ");
    }

    #[test]
    fn command_line_requires_an_executable() {
        assert!(parse_command_line(&[]).is_err());
        assert!(parse_command_line(&["--detach".to_string()]).is_err());
        assert_eq!(
            parse_command_line(&["--detach".to_string(), String::new()])
                .unwrap_err()
                .to_string(),
            "invalid command line arguments"
        );
    }

    #[test]
    fn command_line_separates_loader_and_game_arguments() {
        let args = vec![
            "--detach".to_string(),
            "game.exe".to_string(),
            "--args=-speedcontrol".to_string(),
        ];
        let command = parse_command_line(&args).unwrap();
        assert_eq!(command.executable_name, "game.exe");
        assert_eq!(command.syringe_arguments, vec!["--detach"]);
        assert_eq!(command.game_arguments, "-speedcontrol");
    }

    #[test]
    fn replace_replaces_all_matches() {
        assert_eq!(replace("a%1b%1c", "%1", "X"), "aXbXc");
    }

    #[test]
    fn replace_handles_empty_and_single_byte_patterns() {
        assert_eq!(replace("abc", "", "X"), "abc");
        assert_eq!(replace("a", "a", "X"), "X");
        assert_eq!(replace("abcd", "a", "X"), "Xbcd");
        assert_eq!(replace("aaa", "aa", "b"), "ba");
    }
}
