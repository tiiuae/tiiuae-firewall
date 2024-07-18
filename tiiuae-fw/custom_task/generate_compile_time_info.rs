use chrono::{DateTime, Utc};
use std::process::Command;
pub fn main() {
    // Get the current timestamp
    // Get the current date and time in ISO 8601 format
    let now: DateTime<Utc> = Utc::now();
    let formatted_time = now.to_rfc3339();

    // Get the current git commit SHA
    let git_sha = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("Failed to get git SHA")
        .stdout;
    let git_sha = String::from_utf8(git_sha)
        .expect("Invalid UTF-8")
        .trim()
        .to_string();

    let git_commit_date_time = Command::new("git")
        .arg("show")
        .arg("-s")
        .arg("--format=%ci")
        .arg("HEAD")
        .output()
        .expect("Failed to get git commit date and time")
        .stdout;
    let git_commit_date_time = String::from_utf8(git_commit_date_time)
        .expect("Invalid UTF-8")
        .trim()
        .to_string();

    let git_commit_author_name = Command::new("git")
        .arg("show")
        .arg("-s")
        .arg("--format=%an")
        .arg("HEAD")
        .output()
        .expect("Failed to get git commit date and time")
        .stdout;
    let git_commit_author_name = String::from_utf8(git_commit_author_name)
        .expect("Invalid UTF-8")
        .trim()
        .to_string();
    let git_commit_author_email = Command::new("git")
        .arg("show")
        .arg("-s")
        .arg("--format=%ae")
        .arg("HEAD")
        .output()
        .expect("Failed to get git commit date and time")
        .stdout;
    let git_commit_author_email = String::from_utf8(git_commit_author_email)
        .expect("Invalid UTF-8")
        .trim()
        .to_string();
    // Set environment variables

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=BUILD_TIMESTAMP_UTC={}", formatted_time);
    println!("cargo:rustc-env=GIT_SHA={}", git_sha);
    println!(
        "cargo:rustc-env=GIT_COMMIT_DATE_TIME={}",
        git_commit_date_time
    );
    println!(
        "cargo:rustc-env=GIT_COMMIT_AUTHOR_NAME={}",
        git_commit_author_name
    );
    println!(
        "cargo:rustc-env=GIT_COMMIT_EMAIL={}",
        git_commit_author_email
    );
}
