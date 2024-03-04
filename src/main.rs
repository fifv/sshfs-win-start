#![windows_subsystem = "windows"]
use core::time;
use std::{
    fs::File,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::sleep,
};

use tray_item::{IconSource, TrayItem};
enum Message {
    Quit,
    ChangeIcon,
    Reconnect,
    Hello,
}
const IS_DEBUG: bool = true;
fn main() {
    let bin = "C:/Program Files/SSHFS-Win/bin/sshfs.exe";
    let conns = vec![
        Connection {
            user: String::from("root"),
            host: String::from("192.168.31.11"),
            folder: String::from("/media/fuserdata"),
            mountPoint: String::from("X:"),
            port: String::from("22"),
            name: String::from("root@fjail/fuserdata"),
            uuid: String::from("be094dd7-6814-4051-b1cf-8858b35a444c"),
            identityFile: String::from("C:/Users/Fifv/.ssh/id_ed255519"),
            isMountAsANetworkDrive: true,
        },
        Connection {
            user: String::from("root"),
            host: String::from("192.168.31.11"),
            folder: String::from("/media/BitTorrentDownload/"),
            mountPoint: String::from("Y:"),
            port: String::from("22"),
            name: String::from("root@fjail/BitTorrentDownload/"),
            uuid: String::from("cbb57576-a793-4f43-9b6a-cc20dfb3d233"),
            identityFile: String::from("C:/Users/Fifv/.ssh/id_ed255519"),
            isMountAsANetworkDrive: true,
        },
        Connection {
            user: String::from("root"),
            host: String::from("192.168.31.11"),
            folder: String::from("/"),
            mountPoint: String::from("Z:"),
            port: String::from("22"),
            name: String::from("root@fjail"),
            uuid: String::from("718c9c70-d564-4981-8402-4a23b089d874"),
            identityFile: String::from("C:/Users/Fifv/.ssh/id_ed255519"),
            isMountAsANetworkDrive: true,
        },
        Connection {
            user: String::from("fifv"),
            host: String::from("192.168.56.102"),
            folder: String::from("/"),
            mountPoint: String::from("R:"),
            port: String::from("22"),
            name: String::from("fifv@VB.Arch/"),
            uuid: String::from("wwwwwwwww"),
            identityFile: String::from("C:/Users/Fifv/.ssh/id_ed255519"),
            isMountAsANetworkDrive: false,
        },
    ];
    let mut childs = Vec::from_iter(conns.iter().map(|conn| start_app(bin, &conn)));

    /* handler ctrlc. but with no console you can't send ^C ... */
    // let (tx, rx) = mpsc::channel();
    // ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
    //     .expect("Error setting Ctrl-C handler");
    // println!("Waiting for Ctrl-C...");
    // rx.recv().expect("Could not receive from channel.");
    // println!("Got it! Exiting...");


    let mut tray = TrayItem::new(
        "Tray Example",
        IconSource::Resource("name-of-icon-in-rc-file"),
    )
    .unwrap();

    let label_id = tray.inner_mut().add_label_with_id("Tray Label").unwrap();

    tray.inner_mut().add_separator().unwrap();

    let (tx, rx) = mpsc::sync_channel(1);

    let hello_tx = tx.clone();
    tray.add_menu_item("Hello!", move || {
        hello_tx.send(Message::Hello).unwrap();
    })
    .unwrap();

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

    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                for child in &mut childs {
                    println!("* kill {}", child.id());
                    child.kill().expect("failed to kill");
                }
                // childs
                //     .iter()
                //     .for_each(|mut child| child.kill().expect("failed to kill"));
                println!("Quit");
                break;
            }
            Ok(Message::Hello) => {
                tray.inner_mut().set_label("Hi there!", label_id).unwrap();
            }
            Ok(Message::Reconnect) => {
                tray.inner_mut()
                    .set_label("Reconnecting...", reconnect_id)
                    .unwrap();
                // sleep(time::Duration::from_millis(1000));
                // TODO: Reconnect
                for child in &mut childs {
                    println!("* kill {}", child.id());
                    child.kill().expect("failed to kill");
                }
                childs = Vec::from_iter(conns.iter().map(|conn| start_app(bin, &conn)));
                tray.inner_mut()
                    .set_menu_item_label("Reconnect", reconnect_id)
                    .unwrap();
            }
            _ => {}
        }
    }
}
struct Connection {
    user: String,
    host: String,
    folder: String,
    mountPoint: String,
    port: String,
    name: String,
    uuid: String,
    identityFile: String,
    isMountAsANetworkDrive: bool,
}
fn start_app(bin: &str, conn: &Connection) -> Child {
    // println!("* start {}", conn.name);
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut cmd = Command::new(&bin);
    cmd.args([
        format!("{}@{}:{}", conn.user, conn.host, conn.folder),
        conn.mountPoint.to_string(),
        format!("-p{}", conn.port),
        format!("-ovolname={}", conn.name),
    ]);
    if IS_DEBUG {
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
    if conn.isMountAsANetworkDrive {
        cmd.arg(format!("-oVolumePrefix=/sshfs-win-manager/{}", conn.uuid));
    }
    cmd.args(["-oreconnect", "-oPreferredAuthentications=publickey"])
        .arg(format!("-oIdentityFile=\"\"{}\"\"", conn.identityFile));
    // cmd.arg("-ossh_command=bin/ssh.exe");
    cmd.env("PATH", bin.trim_end_matches(|x| x != '/'));


    let stdio_out = Stdio::from(File::create("log_out.txt").unwrap());
    let stdio_err = Stdio::from(File::create("log_err.txt").unwrap());
    let stdio_in = Stdio::from(File::create("log_in.txt").unwrap());
    let child = cmd
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(stdio_in) // this required if creation_flags(CREATE_NO_WINDOW). while stdout and stderr are optional
        .stdout(stdio_out)
        .stderr(stdio_err)
        .spawn()
        .expect("exec failed?!");


    println!("* {} spawned, id: {}", conn.name, child.id());
    child
    // .map(|_| ())
    // .map_err(|e| io::Error::new(io::ErrorKind::Other, e))

    // match child {
    //     Ok(s) => {
    //         print!("rustc succeeded and stdout was:\n",);
    //     }
    //     Err(err) => {
    //         print!("rustc failed and stderr was:\n{}", err);
    //     }
    // }
}
