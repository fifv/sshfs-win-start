## SSHFS Win Start

A non-GUI, tray-only alternative to sshfs-win-manager

Currently only support publickey auth

This project is experimental, and is my first rust app, learning while coding...

## Usage

1. Install `sshfs-win` (maybe also `winfsp`), you can config where `sshfs.exe` located in `sshfs.toml` (default to `C:/Program Files/SSHFS-Win/bin/sshfs.exe`)
2. Copy `sshfs.toml` to the same folder as the `start-sshfs.exe`, then edit it
3. Double-click `start-sshfs.exe`
4. You can quit or reload config by clicking on the tray icon

## Build

1. Install rust
2. Run `cargo build --release`
3. Find output at `target/release/start-sshfs.exe` 
4. Edit & Copy the `sshfs.toml`

## LICENSE
GPL 3.0