use regex::Regex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf, MAIN_SEPARATOR};

// use crate::output::{print_message, OutputLevel};
#[derive(PartialEq, PartialOrd, Debug)]
pub enum OutputLevel {
    Debug,
    Warn,
    Info,
}

pub const CURRENT_OUTPUT_LEVEL: OutputLevel = OutputLevel::Warn;

pub fn print_message(message: &str, level: OutputLevel) {
    if level >= CURRENT_OUTPUT_LEVEL {
        println!("{}", message);
    }
}

pub fn extract_function_name(declaration: &str) -> String {
    let re = Regex::new(r"\s((?:[^`\s(]+(?:`[^']*')?)+)(?:\s*\(|\s*$)").unwrap();
    if let Some(captures) = re.captures(declaration) {
        if let Some(function_name) = captures.get(1) {
            return function_name.as_str().trim_end_matches("()").to_string();
        }
    }
    String::new()
}

pub fn sanitize_filename(name: &str) -> String {
    let invalid_chars: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

    name.chars()
        .map(|c| {
            if invalid_chars.contains(&c) || c == MAIN_SEPARATOR {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim_start_matches('_')
        .trim_end_matches('_')
        .to_string()
}

pub fn clean_output_directory(dir: &str) -> io::Result<()> {
    println!("Cleaning output directory: {}", dir);
    let path = Path::new(dir);
    if path.exists() {
        for entry in wrap_error(
            fs::read_dir(path),
            &format!("Failed to read directory {}", dir),
        )? {
            let entry = wrap_error(entry, "Failed to read directory entry")?;
            let path = entry.path();
            if path.is_dir() {
                wrap_error(
                    fs::remove_dir_all(&path),
                    &format!("Failed to remove directory {:?}", path),
                )?;
            } else {
                wrap_error(
                    fs::remove_file(&path),
                    &format!("Failed to remove file {:?}", path),
                )?;
            }
        }
    } else {
        println!("Output directory does not exist, creating it.");
        wrap_error(
            fs::create_dir_all(path),
            &format!("Failed to create directory {}", dir),
        )?;
    }
    Ok(())
}

pub fn prepare_output_directory(input_path: &Path, output_dir: &str) -> io::Result<String> {
    print_message("Preparing output directory...", OutputLevel::Info);
    let input_file_name = Path::new(input_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let sub_output_dir = PathBuf::from(output_dir).join(input_file_name);
    wrap_error(
        fs::create_dir_all(&sub_output_dir),
        &format!("Failed to create output directory {:?}", sub_output_dir),
    )?;

    Ok(sub_output_dir.to_string_lossy().into_owned())
}

pub fn wrap_error<T>(result: io::Result<T>, context: &str) -> io::Result<T> {
    result.map_err(|e| {
        let error_message = format!("{}: {}", context, e);
        print_error(&error_message);
        io::Error::new(io::ErrorKind::Other, error_message)
    })
}

pub fn print_error(message: &str) {
    const RED: &str = "\x1b[31m";
    const RESET: &str = "\x1b[0m";
    eprintln!("{}Error: {}{}", RED, message, RESET);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_output_level_ordering() {
        assert!(OutputLevel::Debug < OutputLevel::Info);
        assert!(OutputLevel::Info > OutputLevel::Debug);
        assert_eq!(OutputLevel::Info <= CURRENT_OUTPUT_LEVEL, true);
    }

    #[test]
    fn test_output_level_equality() {
        assert_eq!(OutputLevel::Info, OutputLevel::Info);
        assert_ne!(OutputLevel::Info, OutputLevel::Debug);
        assert_ne!(OutputLevel::Warn, OutputLevel::Debug);
    }

    #[test]
    fn test_extract_function_name() {
        assert_eq!(
            extract_function_name("void test_function(int a)"),
            "test_function"
        );
        assert_eq!(
            extract_function_name("int complex_function_name(char* b, int c)"),
            "complex_function_name"
        );
        assert_eq!(
            extract_function_name("struct Result* get_result()"),
            "get_result"
        );
        assert_eq!(
            extract_function_name(
                "__int64 __fastcall CSslContext::MakeSessionKeys(CSslContext *this, __int64 a2)"
            ),
            "CSslContext::MakeSessionKeys"
        );
        assert_eq!(extract_function_name("CSessionCacheClientItem *__fastcall CSessionCacheClientItem::`vector deleting destructor'()"),"CSessionCacheClientItem::`vector deleting destructor'");
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal_filename"), "normal_filename");
        assert_eq!(
            sanitize_filename("file:name?with*invalid<chars>"),
            "file_name_with_invalid_chars"
        );
        assert_eq!(
            sanitize_filename("CSslContext::MakeSessionKeys"),
            "CSslContext__MakeSessionKeys"
        );
        assert_eq!(
            sanitize_filename("__leading_underscores__"),
            "leading_underscores"
        );
        assert_eq!(
            sanitize_filename("trailing_underscores__"),
            "trailing_underscores"
        );
        assert_eq!(
            sanitize_filename("file/name\\with/backslashes"),
            "file_name_with_backslashes"
        );
    }

    #[test]
    fn test_wrap_error_success() {
        let result: io::Result<i32> = Ok(42);
        let wrapped = wrap_error(result, "Test context");
        assert_eq!(wrapped.unwrap(), 42);
    }

    #[test]
    fn test_wrap_error_failure() {
        let error = io::Error::new(io::ErrorKind::NotFound, "Original error");
        let result: io::Result<i32> = Err(error);
        let wrapped = wrap_error(result, "Test context");

        assert!(wrapped.is_err());
        let err = wrapped.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "Test context: Original error");
    }
}
