use clap::{Arg, Command};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use chrono::Local;

mod check_tfhe_docs_are_tested;
mod format_latex_doc;
mod utils;
use log::info;
// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------

static DRY_RUN: AtomicBool = AtomicBool::new(false);

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

const FORMAT_LATEX_DOC: &str = "format_latext_doc";
const CHECK_TFHE_DOCS_ARE_TESTED: &str = "check_tfhe_docs_are_tested";

fn main() -> Result<(), std::io::Error> {
    // We parse the input args
    let matches = Command::new("tasks")
        .about("Rust scripts runner")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Prints debug messages"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Do not execute the commands"),
        )
        .arg(
            Arg::new("test")
                .long("test")
                .help("a test command"),
        )
        .subcommand(Command::new(FORMAT_LATEX_DOC).about("Escape underscores in latex equations"))
        .subcommand(
            Command::new(CHECK_TFHE_DOCS_ARE_TESTED)
                .about("Check that doc files with rust code blocks are tested"),
        )
        .arg_required_else_help(true)
        .get_matches();

    // We initialize the logger with proper verbosity
    let verb = if matches.contains_id("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    CombinedLogger::init(vec![TermLogger::new(
        verb,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    // We set the dry-run mode if present
    if matches.contains_id("dry-run") {
        DRY_RUN.store(true, Relaxed);
    }

    if matches.subcommand_matches(FORMAT_LATEX_DOC).is_some() {
        format_latex_doc::escape_underscore_in_latex_doc()?;
    } else if matches
        .subcommand_matches(CHECK_TFHE_DOCS_ARE_TESTED)
        .is_some()
    {
        check_tfhe_docs_are_tested::check_tfhe_docs_are_tested()?;
    }



    if matches.contains_id("test") {
        info!("Test command executed");
    }

    test_process();
    Ok(())
}


#[cfg(test)]
fn main_test() {
    // This is a test function to run the main function in a test context
    // It is not used in the actual code, but can be used for testing purposes
    info!("Test function executed");
    test_process();
}

// -------------------------------------------------------------------------------------------------
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, ClientKey, CompressedServerKey};

fn test_process() -> Result<(), Box<dyn std::error::Error>> {
    let mut now = Local::now();
    info!("[{}] start process init...", now.format("%Y-%m-%d %H:%M:%S%.3f"));
    // Basic configuration to use homomorphic integers
    //let config = ConfigBuilder::default().build();

    let config = ConfigBuilder::default().build();

    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let gpu_key = compressed_server_key.decompress_to_gpu();


    // Key generation
   // let (client_key, server_keys) = generate_keys(config);

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    // Encrypting the input data using the (private) client_key
    // FheUint32: Encrypted equivalent to u32
    let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // FheUint8: Encrypted equivalent to u8
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // On the server side:
    set_server_key(gpu_key);

    now = Local::now();
    info!("[{}] set process server key...", now.format("%Y-%m-%d %H:%M:%S%.3f"));


    // Clear equivalent computations: 1344 * 5 = 6720
    let encrypted_res_mul = &encrypted_a * &encrypted_b;
    let now = Local::now();
    info!("[{}] set process sClear equivalent computations: 1344 * 5 = 6720...", now.format("%Y-%m-%d %H:%M:%S%.3f"));

    // Clear equivalent computations: 6720 >> 5 = 210
    encrypted_a = &encrypted_res_mul >> &encrypted_b;
    let now = Local::now();
    info!("[{}] set process Clear equivalent computations: 6720 >> 5 = 210", now.format("%Y-%m-%d %H:%M:%S%.3f"));

    // Clear equivalent computations: let casted_a = a as u8;
    let casted_a: FheUint8 = encrypted_a.cast_into();
    let now = Local::now();
    info!("[{}] set process Clear equivalent computations: let casted_a = a as u8;", now.format("%Y-%m-%d %H:%M:%S%.3f"));

    // Clear equivalent computations: min(210, 7) = 7
    let encrypted_res_min = &casted_a.min(&encrypted_c);
    let now = Local::now();
    info!("[{}] Clear equivalent computations: min(210, 7) = 7", now.format("%Y-%m-%d %H:%M:%S%.3f"));


    // Operation between clear and encrypted data:
    // Clear equivalent computations: 7 & 1 = 1
    let encrypted_res = encrypted_res_min & 1_u8;

    let now = Local::now();
    info!("[{}] encrpted res...", now.format("%Y-%m-%d %H:%M:%S%.3f"));


    // Decrypting on the client side:
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, 1_u8);
    let now = Local::now();
    info!("[{}] test process executed successfully", now.format("%Y-%m-%d %H:%M:%S%.3f"));
    Ok(())
}