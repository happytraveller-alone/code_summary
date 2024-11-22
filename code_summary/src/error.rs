use std::io;

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