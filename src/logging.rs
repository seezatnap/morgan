use std::io::{self, Write};

use crate::process_manager::is_foreground_worker;
use crate::run_memory::now_unix_ms;

pub fn stdout_line(message: &str) {
    emit_line(false, message);
}

pub fn stderr_line(message: &str) {
    emit_line(true, message);
}

fn emit_line(is_stderr: bool, message: &str) {
    let rendered = if is_foreground_worker() {
        format!("[{}] {}", now_unix_ms(), message)
    } else {
        message.to_string()
    };

    if is_stderr {
        let _ = writeln!(io::stderr(), "{rendered}");
    } else {
        let _ = writeln!(io::stdout(), "{rendered}");
    }
}
