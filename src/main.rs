#![cfg(windows)]
/* show console on debug build */
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions),),
    windows_subsystem = "windows"
)]
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
use winapi::um::winbase::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
};
use winreg::{enums::HKEY_CURRENT_USER, RegKey};
use winrt_notification::{Duration, IconCrop, Sound, Toast};
enum Message {
    Quit,
    // ChangeIcon,
    Reconnect,
    EditConfig,
    // Hello,
}

const CONFIG_FILE_PATH: &str = "sshfs.toml";

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
    // #[serde(default)]
    bin_path: Option<String>,
    connections: Vec<Connection>,
}
// impl Default for SshfsConfig {
//     fn default() -> Self {
//         SshfsConfig{
//             bin_path: String::from("C:/Program Files/SSHFS-Win/bin/sshfs.exe"),
//             connections: vec![],
//         }
//     }
// }

/**
 * Parse sshfs.toml to struct
 * TODO: better error handling
 */
fn read_config(config_path: Option<&str>) -> Result<SshfsConfig, ()> {
    let config_string = fs::read_to_string(config_path.unwrap_or(CONFIG_FILE_PATH));
    match config_string {
        Ok(config_string) => {
            let config: Result<SshfsConfig, _> = toml::from_str(config_string.as_str());
            match config {
                Ok(config) => {
                    println!("* config: {:#?}", config);
                    Result::Ok(config)
                }
                Err(err) => {
                    eprintln!("failed to parse config, err: {}", err.to_string());
                    toast_error("Failed to parse config!", err.to_string().as_str());
                    Result::Err(())
                }
            }
        }
        Err(_) => {
            toast_error(
                "Failed to open config file!",
                ("Please check whether ".to_owned() + CONFIG_FILE_PATH + " exists").as_str(),
            );
            Result::Err(())
        }
    }

    /* .unwrap_or_else(|err| {
        eprintln!("failed to parse config, err: {}", err);
        let default_config = SshfsConfig {
            connections: vec![],
        };
        default_config
    }) */
}

struct ConnectionManager {
    bin: String,
    // conns: Vec<Connection>,
    childs: Vec<Child>,
}
impl ConnectionManager {
    fn build(bin: &str) -> Self {
        Self {
            bin: bin.to_string(),
            childs: vec![],
            // conns: vec![],
        }
    }
    /**
     * the entry point, start all connections, create tray icon, create message loop
     */
    fn start(self: &mut Self) {
        self.start_all();
        self.tray_loop();
    }
    fn get_connections_from_config(self: &mut Self) -> Vec<Connection> {
        match read_config(None) {
            Ok(config) => config.connections,
            _ => {
                vec![]
            }
        }
    }
    /**
     * create the sshfs.exe (`bin`) process with config in `conn`
     */
    fn create_sshfs(bin: &String, conn: &Connection) -> Child {
        // println!("* start {}", conn.name);
        // let id = nanoid!(6);
        let id = conn.calculate_hash().chars().take(6).collect::<String>();
        use std::os::windows::process::CommandExt;
        // const CREATE_NO_WINDOW: u32 = 0x08000000;

        if conn.is_mount_as_a_network_drive {
            let mount_points = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
                .expect("failed to open reg key");
            mount_points
                .create_subkey(format!("##sshfs-start#{}", &id))
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
            cmd.arg(format!("-oVolumePrefix=/sshfs-start/{}", &id));
        }
        cmd.args(["-oreconnect", "-oPreferredAuthentications=publickey"])
            .arg(format!("-oIdentityFile=\"\"{}\"\"", conn.identity_file));
        // cmd.arg("-ossh_command=bin/ssh.exe");
        cmd.env("PATH", bin.trim_end_matches(|x| x != '/'));


        let stdio_out = Stdio::from(File::create(format!("log_out.log")).unwrap());
        let mut err_file = File::create(format!(
            "log_err_{}_{}.log",
            sanitize_filename::sanitize(&conn.name),
            &id
        ))
        .unwrap();
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
        // let stdio_in = Stdio::from(File::create(format!("log_in.txt")).unwrap());
        let child = cmd
            .creation_flags(CREATE_NO_WINDOW)
            // .creation_flags(DETACHED_PROCESS)
            // .creation_flags(CREATE_NEW_PROCESS_GROUP) // this makes CTRL_BREAK_EVENT works! but only in console subsystem
            // .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            // .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
            // .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            // .creation_flags(CREATE_NEW_CONSOLE)
            // .stdin(stdio_in) // this required if creation_flags(CREATE_NO_WINDOW).as well as stdout and stderr
            .stdin(Stdio::null()) // this required if creation_flags(CREATE_NO_WINDOW). as well as stdout and stderr
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
            self.get_connections_from_config()
                .iter()
                .map(|conn| Self::create_sshfs(&self.bin, &conn)),
        );
    }
    /**
     * kill all processes and restart
     */
    fn restart_all(self: &mut Self) {
        self.kill_all();
        self.start_all();
    }
    // fn kill_gracefully(child: &Child) {
    //     unsafe {
    //         libc::signal( libc::SIGTERM,child.id() as usize,);
    //     }
    // }

    /**
     * currently, only these can send ctrl c and stop child process gracefully:
     * 1. console subsystem + NO CREATE_NO_WINDOW + GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0)
     * 2. console subsystem + NO CREATE_NO_WINDOW + CREATE_NEW_PROCESS_GROUP + GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)
     * 3. manually start the sshfs.exe in shell and press ctrl+c
     * 4. manually start the sshfs.exe in windows terminal and close the window
     *
     * these can force kill child process:
     * 1. child.kill()
     * (yeah, mingw kill seems not work on windows)
     *
     * TODO: use pty to get perfect ^C
     */
    fn kill_all(self: &mut Self) {
        for child in &mut self.childs {
            println!("* kill {}", child.id());
            child.kill().expect("failed to kill");

            // signal::kill(Pid::from_raw(child.id()), Signal::SIGTERM).unwrap();
            // let kill = Command::new("kill")
            //     // TODO: replace `TERM` to signal you want.
            //     .args(["-s", "TERM", &child.id().to_string()])
            //     .output()
            //     .expect("1");
            // println!("{:#?}", kill);
            // kill.wait().expect("2");

            // let pid = child.id();
            // unsafe {
            //     let result = winapi::um::wincon::GenerateConsoleCtrlEvent(
            //         winapi::um::wincon::CTRL_BREAK_EVENT,
            //         pid,
            //     );
            //     println!("* ctrlc to {}, result: {}", pid, result);
            // }

            // child.wait().expect("failed to wait exit");
        }
        // unsafe {
        //     let result = winapi::um::wincon::GenerateConsoleCtrlEvent(
        //         winapi::um::wincon::CTRL_BREAK_EVENT,
        //         0,
        //     );
        //     println!("* ctrlc to {}, result: {}", 0, result);
        // }
        for child in &mut self.childs {
            child.wait().expect("failed to wait exit");
        }
        self.childs.clear();
    }

    fn clean_old_reg() {
        let mount_points = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
            .expect("failed to open reg key");

        let old_keys: Vec<String> = mount_points
            .enum_keys()
            .map(|x| x.unwrap())
            .filter(|x| x.starts_with("##sshfs-start#"))
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

        let editconfig_tx = tx.clone();
        tray.add_menu_item("Edit Config File", move || {
            editconfig_tx.send(Message::EditConfig).unwrap();
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
                Ok(Message::EditConfig) => {
                    open::that(CONFIG_FILE_PATH).unwrap_or_else(|_| {
                        toast_error("Failed to open config file", "");
                    });
                }
                _ => {}
            }
        }
    }
}

fn toast_error(title: &str, text: &str) {
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title(&title)
        // .text1("(╯°□°）╯︵ ┻━┻")
        .text2(&text)
        .sound(Some(Sound::Default))
        .duration(Duration::Long)
        .show()
        .expect("unable to toast");
}


fn main() {
    /* TODO: more elegant error handling */
    let bin = match read_config(None) {
        Ok(config) => config
            .bin_path
            .unwrap_or(String::from("C:/Program Files/SSHFS-Win/bin/sshfs.exe")),
        Err(_) => String::from("C:/Program Files/SSHFS-Win/bin/sshfs.exe"),
    };
    if std::path::Path::new(&bin).exists() {
        // TO\DO: read from config file
        // let mut childs = Vec::from_iter(conns.iter().map(|conn| start_app(bin, &conn)));
        // FIXME: if sshfs.exe doesn't exist, it crashes without any prompt
        // FIXME: if winfps doesn't installed, it failed to connect with error kept in log, not good
        let mut man = ConnectionManager::build(&bin);
        man.start();
    } else {
        toast_error(
            "Please install SSHFS first!",
            ("or specify path to sshfs.exe in `".to_owned() + CONFIG_FILE_PATH + "`").as_str(),
        );
    }
}
