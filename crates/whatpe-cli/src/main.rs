use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: whatpe-cli <path-to-exe-or-dll>");
        return ExitCode::FAILURE;
    };

    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("failed to read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let info = match whatpe_core::analyze(&bytes) {
        Ok(info) => info,
        Err(err) => {
            eprintln!("failed to analyze {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!("File: {path}");
    for category in info.categories {
        println!("========== {} ==========", category.name);
        for item in category.items {
            println!("{}: {}", item.name, item.value);
            if let Some(note) = item.note {
                println!("    ({note})");
            }
        }
    }

    ExitCode::SUCCESS
}
