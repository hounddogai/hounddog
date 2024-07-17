#[macro_export]
macro_rules! env_bool {
    ($key:expr) => {
        std::env::var($key)
            .map(|v| v.trim().to_lowercase())
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
    };
    ($key:expr, $default:expr) => {
        std::env::var($key)
            .map(|v| v.trim().to_lowercase())
            .map(|v| v == "1" || v == "true")
            .unwrap_or($default)
    };
}

#[macro_export]
macro_rules! env_str {
    ($key:expr) => {
        std::env::var($key).unwrap_or_default().trim().to_string()
    };
    ($key:expr, $default:expr) => {
        std::env::var($key).unwrap_or_else(|_| $default.to_string()).trim().to_string()
    };
}

#[macro_export]
macro_rules! print_dbg {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!("{}", format!($($arg)*).blue())
        }
    };
}

#[macro_export]
macro_rules! print_warn {
    ($($arg:tt)*) => {
        println!("{}", format!($($arg)*).yellow())
    };
}

#[macro_export]
macro_rules! print_err {
    ($($arg:tt)*) => {
        eprintln!("{}", format!($($arg)*).red())
    };
}

#[macro_export]
macro_rules! print_header {
    ($($arg:tt)*) => {
        println!("{}", format!($($arg)*).bold().underline())
    };
}

#[macro_export]
macro_rules! console_url {
    // If only the URL is provided
    ($url:expr) => {
        format!("{}", $url).truecolor(92, 145, 239).underline()
    };
    ($file:expr, $line:expr, $column:expr) => {
        format!("{}:{}:{}", $file, $line, $column).truecolor(92, 145, 239).underline()
    };
}

#[macro_export]
macro_rules! console_label {
    (sensitivity: $sensitivity:expr) => {
        match $sensitivity {
            crate::enums::Sensitivity::Critical => {
                " CRITICAL ".bold().truecolor(255, 255, 255).on_truecolor(255, 0, 0)
            }
            crate::enums::Sensitivity::Medium => {
                "  MEDIUM  ".bold().truecolor(255, 255, 255).on_truecolor(255, 100, 0)
            }
            crate::enums::Sensitivity::Low => {
                "   LOW   ".bold().truecolor(0, 0, 0).on_truecolor(241, 194, 50)
            }
        }
    };
    (severity: $severity:expr) => {{
        match $severity {
            crate::enums::Severity::Critical => {
                " CRITICAL ".bold().truecolor(255, 255, 255).on_truecolor(255, 0, 0)
            }
            crate::enums::Severity::Medium => {
                "  MEDIUM  ".bold().truecolor(255, 255, 255).on_truecolor(255, 100, 0)
            }
            crate::enums::Severity::Low => {
                "   LOW    ".bold().truecolor(0, 0, 0).on_truecolor(241, 194, 50)
            }
        }
    }};
}

#[macro_export]
macro_rules! console_text {
    (sensitivity: $sensitivity:expr, $($arg:tt)*) => {{
        let text = format!($($arg)*);
        match $sensitivity {
            crate::enums::Sensitivity::Critical => $text.bold().truecolor(255, 0, 0),
            crate::enums::Sensitivity::Medium => $text.bold().truecolor(255, 100, 0),
            crate::enums::Sensitivity::Low => $text.bold().truecolor(241, 194, 50)
        }
    }};
    (severity: $severity:expr, $($arg:tt)*) => {{
        let text = format!($($arg)*);
        match $severity {
            crate::enums::Severity::Critical => text.bold().truecolor(255, 0, 0),
            crate::enums::Severity::Medium => text.bold().truecolor(255, 100, 0),
            crate::enums::Severity::Low => text.bold().truecolor(241, 194, 50),
        }
    }};
}

#[macro_export]
macro_rules! console_note {
    ($($arg:tt)*) => {
        format!("{}", format!($($arg)*).dimmed())
    };
}

#[macro_export]
macro_rules! markdown_url {
    ($url:expr) => {
        format!(
            "<span style=\"color:rgba(92, 145, 239, 1); font-family: monospace;\">{}</span>",
            $url
        )
    };
    ($file:expr, $line:expr, $column:expr) => {
        format!(
            "<span style=\"color:rgba(92, 145, 239, 1); font-family: monospace;\">{}:{}:{}</span>",
            $file, $line, $column
        )
    };
}

#[macro_export]
macro_rules! markdown_label {
    (sensitivity: $sensitivity:expr) => {
        match $sensitivity {
            crate::enums::Sensitivity::Critical => format!("<span style=\"color:rgba(255, 255, 255, 1); background-color:rgba(255, 0, 0, 1); font-family: monospace;\">&nbsp;**CRITICAL**&nbsp;</span>"),
            crate::enums::Sensitivity::Medium => format!("<span style=\"color:rgba(255, 255, 255, 1); background-color:rgba(255, 100, 0, 1); font-family: monospace;\">&nbsp;&nbsp;**MEDIUM**&nbsp;&nbsp;</span>"),
            crate::enums::Sensitivity::Low => format!("<span style=\"color:rgba(0, 0, 0, 1); background-color:rgba(241, 194, 50, 1); font-family: monospace;\">&nbsp;&nbsp;&nbsp;**LOW**&nbsp;&nbsp;&nbsp;&nbsp;</span>"),
        }
    };
    (severity: $severity:expr) => {
        match $severity {
            crate::enums::Severity::Critical => format!("<span style=\"color:rgba(255, 255, 255, 1); background-color:rgba(255, 0, 0, 1); font-family: monospace;\">&nbsp;**CRITICAL**&nbsp;</span>"),
            crate::enums::Severity::Medium => format!("<span style=\"color:rgba(255, 255, 255, 1); background-color:rgba(255, 100, 0, 1); font-family: monospace;\">&nbsp;&nbsp;**MEDIUM**&nbsp;&nbsp;</span>"),
            crate::enums::Severity::Low => format!("<span style=\"color:rgba(0, 0, 0, 1); background-color:rgba(241, 194, 50, 1); font-family: monospace;\">&nbsp;&nbsp;&nbsp;**LOW**&nbsp;&nbsp;&nbsp;&nbsp;</span>"),
        }
    };
}

#[macro_export]
macro_rules! markdown_text {
    (sensitivity: $sensitivity:expr, $($arg:tt)*) => {{
        let text = format!($($arg)*);
        match $sensitivity {
            crate::enums::Sensitivity::Critical => format!("<span style=\"color:rgba(255, 0, 0, 1)\">{}</span>", text),
            crate::enums::Sensitivity::Medium => format!("<span style=\"color:rgba(255, 100, 0, 1)\">{}</span>", text),
            crate::enums::Sensitivity::Low => format!("<span style=\"color:rgba(241, 194, 50, 1)\">{}</span>", text)
        }
    }};
    (severity: $severity:expr, $($arg:tt)*) => {{
        let text = format!($($arg)*);
        match $severity {
            crate::enums::Severity::Critical => format!("<span style=\"color:rgba(255, 0, 0, 1)\">{}</span>", text),
            crate::enums::Severity::Medium => format!("<span style=\"color:rgba(255, 100, 0, 1)\">{}</span>", text),
            crate::enums::Severity::Low => format!("<span style=\"color:rgba(241, 194, 50, 1)\">{}</span>", text)
        }
    }};

}

#[macro_export]
macro_rules! markdown_note {
    ($($arg:tt)*) => {
        format!("<span style=\"color:rgba(100, 100, 100, 1)\">{}</span>", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        anyhow::anyhow!(crate::HoundDogError {
            message: format!($($arg)*),
            sentry: false
        })
    };
}

#[macro_export]
macro_rules! sentry_err {
    ($($arg:tt)*) => {
        anyhow::anyhow!(crate::error::HoundDogError {
            message: format!($($arg)*),
            sentry: true
        })
    };
}
