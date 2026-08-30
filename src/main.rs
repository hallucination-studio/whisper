//! Command-line entry point for configuration validation.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
#[cfg(feature = "development-fixture")]
use std::process::Command;
use std::process::ExitCode;

use whisper::{Config, ConfigError, parse_config};

#[cfg(not(target_arch = "wasm32"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();

    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };

    if command == "check-config" {
        return check_config_command(args.collect());
    }

    if command == "init-admission" {
        return init_admission_command(args.collect());
    }

    if command == "serve" {
        return serve_command(args.collect());
    }

    #[cfg(feature = "development-fixture")]
    if command == "development-fixture" {
        return development_fixture_command(args.collect());
    }

    eprintln!("unknown command");
    print_usage();
    ExitCode::from(2)
}

fn check_config_command(args: Vec<OsString>) -> ExitCode {
    let [path] = args.as_slice() else {
        print_usage();
        return ExitCode::from(2);
    };
    match check_config(Path::new(path)) {
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

fn init_admission_command(args: Vec<OsString>) -> ExitCode {
    let [path] = args.as_slice() else {
        print_usage();
        return ExitCode::from(2);
    };
    let config = match check_config(Path::new(path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            return ExitCode::from(1);
        }
    };
    match whisper::init_admission(&config) {
        Ok(()) => {
            println!("initialized admission Store");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Store initialization failed: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(unix)]
fn serve_command(args: Vec<OsString>) -> ExitCode {
    let [path] = args.as_slice() else {
        print_usage();
        return ExitCode::from(2);
    };
    let config = match check_config(Path::new(path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            return ExitCode::from(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Host async runtime startup failed: {error}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let host = match whisper::HostRuntime::start(&config).await {
            Ok(host) => host,
            Err(error) => {
                eprintln!("Host runtime startup failed: {error}");
                return ExitCode::from(1);
            }
        };
        let capture = host.capture_address();
        let http = host.http_address();
        println!("Host runtime started: capture={capture} http={http}");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("Host shutdown signal failed: {error}");
                    return ExitCode::from(1);
                }
            }
            () = host.wait_for_stop() => {}
        }
        match host.shutdown().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Host runtime shutdown failed: {error}");
                ExitCode::from(1)
            }
        }
    })
}

#[cfg(not(unix))]
fn serve_command(args: Vec<OsString>) -> ExitCode {
    let [path] = args.as_slice() else {
        print_usage();
        return ExitCode::from(2);
    };
    if let Err(error) = check_config(Path::new(path)) {
        eprintln!("invalid configuration: {error}");
        return ExitCode::from(1);
    }
    eprintln!("Host runtime startup failed: unsupported Managed-store platform");
    ExitCode::from(1)
}

#[cfg(feature = "development-fixture")]
fn development_fixture_command(args: Vec<OsString>) -> ExitCode {
    let [config_path, sensor_id, program, child_args @ ..] = args.as_slice() else {
        print_usage();
        return ExitCode::from(2);
    };
    let Some(sensor_id) = sensor_id.to_str() else {
        eprintln!("development fixture Sensor ID must be UTF-8");
        return ExitCode::from(2);
    };
    let config = match check_config(Path::new(config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid configuration: {error}");
            return ExitCode::from(1);
        }
    };
    let mut child = Command::new(program);
    child.args(child_args);
    match whisper::development_fixture::run(&config, sensor_id, &mut child) {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or_else(|| ExitCode::from(1), ExitCode::from),
        Err(error) => {
            eprintln!("development fixture failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    eprintln!("usage: whisper check-config <path>");
    eprintln!("       whisper init-admission <path>");
    eprintln!("       whisper serve <path>");
    #[cfg(feature = "development-fixture")]
    eprintln!(
        "       whisper development-fixture <config-path> <sensor-id> <program> [arguments...]"
    );
}

fn check_config(path: &Path) -> Result<Config, ConfigError> {
    let contents = fs::read_to_string(path).map_err(ConfigError::read)?;
    parse_config(&contents)
}
