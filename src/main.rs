//! Command-line entry point for configuration validation.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use world::{ConfigError, EffectiveConfig, parse_config};

#[cfg(not(target_arch = "wasm32"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();

    let Some(command) = args.next() else {
        eprintln!("usage: world check-config <path>");
        return ExitCode::from(2);
    };

    if command != "check-config" {
        eprintln!("unknown command; expected check-config");
        return ExitCode::from(2);
    }

    let Some(path) = args.next() else {
        eprintln!("usage: world check-config <path>");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprintln!("check-config accepts exactly one path");
        return ExitCode::from(2);
    }

    match check_config(Path::new(&path)) {
        Ok(config) => {
            println!("valid configuration: {}", config.deployment().id());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            ExitCode::from(1)
        }
    }
}

fn check_config(path: &Path) -> Result<EffectiveConfig, ConfigError> {
    let contents = fs::read_to_string(path).map_err(ConfigError::read)?;
    parse_config(&contents)
}
