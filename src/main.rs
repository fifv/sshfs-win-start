#![windows_subsystem = "windows"]
/**
 * what I have learnt:
 * 1.
 * what I should learn:
 * 1. channel, mspc
 * 2. serde
 * 3. String vs str & or not
 *
 */
use std::{
    fs::{self, File},
    io::Write,
    process::{Child, Command, Stdio},
    sync::mpsc,
};

use serde::{Deserialize, Serialize};
use tray_item::{IconSource, TrayItem};
use winreg::{enums::HKEY_CURRENT_USER, RegKey};
use winrt_notification::{Duration, IconCrop, Sound, Toast};
enum Message {
    Quit,
    // ChangeIcon,
    Reconnect,
    // Hello,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // Automatically map snake_case to camelCase
struct Connection {
    name: String,
    user: String,
    host: String,
    port: String,
    folder: String,
    mount_point: String,
    // uuid: String,
    identity_file: String,
    is_mount_as_a_network_drive: bool,
}
impl Connection {
    // fn calculate_hash_from_everything(&self) -> String {
    //     let serialized = serde_json::to_string(self).unwrap();
    //     let digest = md5::compute(serialized);
    //     format!("{:x}", digest).chars().take(6).collect::<String>()
    // }
    fn calculate_hash(&self) -> String {
        let mut hasher = md5::Context::new();
        hasher.consume(&self.user);
        hasher.consume(&self.host);
        hasher.consume(&self.port);
        hasher.consume(&self.folder);
        let result = hasher.compute();
        format!("{:x}", result).chars().take(6).collect::<String>()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // Automatically map snake_case to camelCase
struct SshfsConfig {
    connections: Vec<Connection>,
}

struct ConnectionManager {
    bin: String,
    conns: Vec<Connection>,
    childs: Vec<Child>,
}
impl ConnectionManager {
    fn build(bin: &str) -> Self {
        Self {
            bin: bin.to_string(),
            childs: vec![],
            conns: vec![],
        }
    }
    /**
     * the entry point, start all connections, create tray icon, create message loop
     */
    fn start(self: &mut Self) {
        match self.read_from_config() {
            Ok(_) => {
                self.start_all();
            }
            _ => (),
        }
        self.tray_loop();
    }
    /**
     * create the sshfs.exe (`bin`) process with config in `conn`
     */
    fn create_sshfs(bin: &String, conn: &Connection) -> Child {
        // println!("* start {}", conn.name);
        // let id = nanoid!(6);
        let id = conn.calculate_hash().chars().take(6).collect::<String>();
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        if conn.is_mount_as_a_network_drive {
            let mount_points = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
                .expect("failed to open reg key");
            mount_points
                .create_subkey(format!("##sshfs#{}", &id))
                .expect("failed to open reg")
                .0
                .set_value("_LabelFromReg", &conn.name)
                .expect("failed to modify reg");
            // Command::new("reg")
            // .arg("add")
            // .arg(format!("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##sshfs#{}",&conn.uuid))
            // .arg("/v").arg("_LabelFromReg")
            // .arg("/d").arg(&conn.name)
            // .arg("/f")
            // .creation_flags(CREATE_NO_WINDOW)
            // .output()
            // .expect("failed to modify reg");
        }

        let mut cmd = Command::new(&bin);
        cmd.args([
            format!("{}@{}:{}", conn.user, conn.host, conn.folder),
            conn.mount_point.to_string(),
            format!("-p{}", conn.port),
            format!("-ovolname={}", conn.name),
        ]);
        if true {
            // TODO: 1. find how to prevent spawn new console without -odebug
            // TO\DO: 2. or use bufWritter to buffer write seems can't use bufWritter...?
            cmd.args([
                /* log write 180KB/s while copy file 100MB/s */
                "-odebug", // this makes kill works...???why???
                // without this, they will create new processes and exit themselves
                "-olOglEvel=debug1",
            ]);
        };
        /* seems -o is case-insensitive */
        cmd.args([
            "-oStrictHostKeyChecking=no",
            "-oUserKnownHostsFile=/dev/null",
        ])
        .args([
            "-oidmap=user",
            "-ouid=-1",
            "-ogid=-1",
            "-oumask=000",
            "-ocreate_umask=000",
            "-omax_readahead=1GB",
            "-oallow_other",
            "-olarge_read",
            "-okernel_cache",
            "-ofollow_symlinks",
            // "-omax_conns=8", // no effect
            // "-oThreadCount=8", // no effect
            // "-oCiphers=arcfour", // not supported
            // "-oCiphers=chacha20-poly1305@openssh.com", // no effect
            // "-oCompression=no", // no effect
        ]);
        if conn.is_mount_as_a_network_drive {
            cmd.arg(format!("-oVolumePrefix=/sshfs/{}", &id));
        }
        cmd.args(["-oreconnect", "-oPreferredAuthentications=publickey"])
            .arg(format!("-oIdentityFile=\"\"{}\"\"", conn.identity_file));
        // cmd.arg("-ossh_command=bin/ssh.exe");
        cmd.env("PATH", bin.trim_end_matches(|x| x != '/'));


        let stdio_out = Stdio::from(File::create(format!("log_out.txt")).unwrap());
        let mut err_file = File::create(format!("log_err_{}.txt", id)).unwrap();
        err_file
            .write_all(
                format!(
                    "------- config -------\n\n{:#?}\n\n------- stderr -------\n\n",
                    conn
                )
                .as_bytes(),
            )
            .expect("");
        let stdio_err = Stdio::from(err_file);
        let stdio_in = Stdio::from(File::create(format!("log_in.txt")).unwrap());
        let child = cmd
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(stdio_in) // this required if creation_flags(CREATE_NO_WINDOW). while stdout and stderr are optional
            .stdout(stdio_out)
            .stderr(stdio_err)
            .spawn()
            .expect("exec failed?!");


        println!("* [spawned] pid: {} , name: {}", child.id(), conn.name);
        child
    }

    fn start_all(self: &mut Self) {
        Self::clean_old_reg();
        self.childs = Vec::from_iter(
            self.conns
                .iter()
                .map(|conn| Self::create_sshfs(&self.bin, &conn)),
        );
    }
    /**
     * kill all processes and restart
     */
    fn restart_all(self: &mut Self) {
        match self.read_from_config() {
            Ok(_) => {
                self.kill_all();
                self.start_all();
            }
            _ => (),
        }
    }
    fn kill_all(self: &mut Self) {
        for child in &mut self.childs {
            println!("* kill {}", child.id());
            child.kill().expect("failed to kill");
        }
        self.childs.clear();
    }
    fn read_from_config(self: &mut Self) -> Result<(), ()> {
        let config: Result<SshfsConfig,_> = toml::from_str(
            fs::read_to_string("sshfs.toml")
                .expect("failed to open config")
                .as_str(),
        )
        /* .unwrap_or_else(|err| {
            eprintln!("failed to parse config, err: {}", err);
            let default_config = SshfsConfig {
                connections: vec![],
            };
            default_config
        }) */;
        match config {
            Ok(config) => {
                println!("* config: {:#?}", config);
                self.conns = config.connections;
                Result::Ok(())
            }
            Err(err) => {
                eprintln!("failed to parse config, err: {}", err.to_string());
                Toast::new(Toast::POWERSHELL_APP_ID)
                    .title("Failed to parse config!")
                    // .text1("(╯°□°）╯︵ ┻━┻")
                    .text2(err.to_string().as_str())
                    .sound(Some(Sound::Default))
                    .duration(Duration::Long)
                    .show()
                    .expect("unable to toast");
                Result::Err(())
            }
        }
    }
    fn clean_old_reg() {
        let mount_points = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
            .expect("failed to open reg key");

        let old_keys: Vec<String> = mount_points
            .enum_keys()
            .map(|x| x.unwrap())
            .filter(|x| x.starts_with("##sshfs#"))
            .collect();
        /*
        what? move filter into forin cause omit some keys?
         */
        for old_key in old_keys {
            mount_points
                .delete_subkey(&old_key)
                .expect("failed to clean old key");
            println!("* [clean reg] deleted: {}", &old_key);
        }
    }
    fn tray_loop(self: &mut Self) {
        let mut tray = TrayItem::new(
            "SSHFS Win Start",
            IconSource::Resource("name-of-icon-in-rc-file"),
        )
        .unwrap();

        let (tx, rx) = mpsc::sync_channel(1);

        let reconnect_tx = tx.clone();
        let reconnect_id = tray
            .inner_mut()
            .add_menu_item_with_id("Reconnect", move || {
                reconnect_tx.send(Message::Reconnect).unwrap();
            })
            .unwrap();

        tray.inner_mut().add_separator().unwrap();

        let quit_tx = tx.clone();
        tray.add_menu_item("Quit", move || {
            quit_tx.send(Message::Quit).unwrap();
        })
        .unwrap();

        /* handle ctrlc, only works in console subsystem, not windows subsystem */
        let ctrlc_tx = tx.clone();
        ctrlc::set_handler(move || {
            println!("Receive Ctrl-C, exiting...");
            ctrlc_tx
                .send(Message::Quit)
                .expect("Could not send signal on channel.")
        })
        .expect("Error setting Ctrl-C handler");


        loop {
            match rx.recv() {
                Ok(Message::Quit) => {
                    self.kill_all();
                    println!("Quit");
                    break;
                }
                Ok(Message::Reconnect) => {
                    tray.inner_mut()
                        .set_label("Reconnecting...", reconnect_id)
                        .unwrap();
                    // sleep(time::Duration::from_millis(1000));
                    // TO\DO: Reconnect
                    self.restart_all();
                    tray.inner_mut()
                        .set_menu_item_label("Reconnect", reconnect_id)
                        .unwrap();
                }
                _ => {}
            }
        }
    }
}


fn main() {
    let bin = "C:/Program Files/SSHFS-Win/bin/sshfs.exe";
    // TO\DO: read from config file
    // let mut childs = Vec::from_iter(conns.iter().map(|conn| start_app(bin, &conn)));
    let mut man = ConnectionManager::build(bin);
    man.start();
}
