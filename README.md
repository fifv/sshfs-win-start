## SSHFS Win Start

A no-GUI alternative to sshfs-win-manager

Currently only support publickey auth

## Usage


1. Install `sshfs-win`, make sure `sshfs.exe` located at `C:/Program Files/SSHFS-Win/bin/sshfs.exe`
2. Edit `sshfs.toml`, copy it in the same folder as the `start-sshfs.exe`
3. Double-Click the `start-sshfs.exe`
4. You can quit or reload config by click on the tray icon

## Build

1. Install rust
2. run `cargo build --release`
3. output at `target/release` 
4. Edit & Copy the `sshfs.toml`