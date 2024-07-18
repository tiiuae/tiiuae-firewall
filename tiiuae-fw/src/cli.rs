/*
    Copyright 2022-2024 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
pub mod cli_impl {
    use clap::{ArgAction, Parser};
    use lazy_static::lazy_static;
    use std::env;
    use std::error::Error;
    use std::fs;
    use std::path::Path;
    lazy_static! {
        pub static ref CLI_ARGS: Args = {


            // Initialize the IP address using a function or any other logic
            let args=handling_args().expect("Error in argument handling");
            println!("{args:?}");
            args
        };
    }

    const VERSION: &str = concat!(
        "\nversion: ",
        env!("CARGO_PKG_VERSION"),
        "\ncommit sha: ",
        env!("GIT_SHA"),
        "\ncommit date: ",
        env!("GIT_COMMIT_DATE_TIME"),
        "\nauthor name: ",
        env!("GIT_COMMIT_AUTHOR_NAME"),
        "\nauthor e-mail: ",
        env!("GIT_COMMIT_EMAIL"),
        "\nbuild timestamp(utc): ",
        env!("BUILD_TIMESTAMP_UTC"),
        "\nlicense: ",
        env!("CARGO_PKG_LICENSE")
    );

    /// tiiuae firewall
    #[derive(Parser, Debug)]
    #[command(author, about, long_about =None ,version =VERSION)]
    pub struct Args {
        /// Configuration file path
        #[arg(short,long,default_value_t=String::from("tiiuae-fw/src/tests/config_all_valid.toml"),value_parser=is_config_file_exists)]
        pub config_file: String,

        /// Log severity
        #[arg(long, default_value_t = String::from("debug"))]
        pub log_level: String,

        #[arg(long,action = ArgAction::SetTrue, help = "Enable/Disable log")]
        pub log: bool,
    }

    fn is_on_off(s: &str) -> Result<String, String> {
        let val: String = s.parse().map_err(|_| format!("`{s}` isn't a string"))?;
        if val == "on" || val == "off" {
            Ok(val)
        } else {
            Err("Value can be on or off".to_string())
        }
    }

    fn is_config_file_exists(path: &str) -> Result<String, String> {
        // Convert the path to a `Path` object
        let path = Path::new(path);

        // Check if the metadata exists and if it is a file
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(format!("File exists: {}", path.display())),
            Ok(_) => Err("Path exists but is not a file.".to_string()),
            Err(e) => Err(format!("Error checking file: {}", e)),
        }
    }

    fn handling_args() -> Result<Args, Box<dyn Error>> {
        let args: Args = Args::parse();

        Ok(args)
    }
}
