// File: tests/cli_tests.rs

#[test]
fn test_cli_backup_args() {
    let app = build_cli(); // builds the CLI using Clap
    let matches = app.get_matches_from(vec!["coinswap", "backup", "--no-cloud"]);
    assert!(matches.subcommand_matches("backup").unwrap().is_present("no-cloud"));
}

#[test]
fn test_cli_restore_requires_file() {
    let app = build_cli();
    let result = app.get_matches_from_safe(vec!["coinswap", "restore"]);
    assert!(result.is_err(), "Restore should require a file path");
}
