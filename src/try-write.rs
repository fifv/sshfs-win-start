use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

fn main() {
    // try_kill();
    // win32_kill();
    // win32_terminate();
    win32_wmclose();
}
fn try_kill() {
    let pid = 50216;
    unsafe {
        let result =
            winapi::um::wincon::GenerateConsoleCtrlEvent(winapi::um::wincon::CTRL_C_EVENT, pid);
        println!("kill {} result:{}", pid, result);
    };
}
fn win32_kill() {
    // Process ID of the process to be terminated
    let pid_to_terminate = 50216; // Replace with the actual PID of the process

    // Open the process with terminate access
    let process_handle = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_TERMINATE,
            winapi::shared::minwindef::FALSE,
            pid_to_terminate,
        )
    };

    // Check if the process handle is valid
    if process_handle.is_null() {
        println!("Failed to open process. Error code: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return;
    }

    // Terminate the process
    let result = unsafe { winapi::um::processthreadsapi::TerminateProcess(process_handle, 1) };

    // Check the result of the termination
    if result == winapi::shared::minwindef::FALSE {
        println!("Failed to terminate process. Error code: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
    } else {
        println!("Process terminated successfully.");
    }
}

fn win32_terminate() {
    fn get_process_id(process_name: &str) -> Option<u32> {
        let process_name_cstr = CString::new(process_name).unwrap();
        unsafe {
            let snapshot = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
                winapi::um::tlhelp32::TH32CS_SNAPPROCESS,
                0,
            );
            if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return None;
            }

            let mut entry = winapi::um::tlhelp32::PROCESSENTRY32 {
                dwSize: std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32,
                ..std::mem::zeroed()
            };

            if winapi::um::tlhelp32::Process32First(snapshot, &mut entry)
                == winapi::shared::minwindef::FALSE
            {
                winapi::um::handleapi::CloseHandle(snapshot);
                return None;
            }

            loop {
                let process_name = CString::from_vec_unchecked(
                    entry
                        .szExeFile
                        .iter()
                        .map(|&x| x as u8)
                        .take_while(|&x| x != 0)
                        .collect(),
                );
                if process_name.to_string_lossy().to_lowercase()
                    == process_name_cstr.to_string_lossy().to_lowercase()
                {
                    winapi::um::handleapi::CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if winapi::um::tlhelp32::Process32Next(snapshot, &mut entry)
                    == winapi::shared::minwindef::FALSE
                {
                    break;
                }
            }

            winapi::um::handleapi::CloseHandle(snapshot);
            None
        }
    }

    fn open_process_handle(process_id: u32) -> Option<*mut winapi::ctypes::c_void> {
        unsafe {
            let handle = winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_TERMINATE | winapi::um::winnt::PROCESS_QUERY_INFORMATION,
                winapi::shared::minwindef::FALSE,
                process_id,
            );
            if handle.is_null() {
                None
            } else {
                Some(handle)
            }
        }
    }

    fn terminate_process(handle: *mut winapi::ctypes::c_void) -> bool {
        unsafe {
            winapi::um::processthreadsapi::TerminateProcess(handle, 0);
            let wait_result =
                winapi::um::synchapi::WaitForSingleObject(handle, winapi::um::winbase::INFINITE);
            wait_result != winapi::um::winbase::WAIT_FAILED
        }
    }

    fn close_handle(handle: *mut winapi::ctypes::c_void) {
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
    }
    let process_name = "notepad.exe"; // Replace this with the name of the process you want to terminate

    if let Some(process_id) = get_process_id(process_name) {
        if let Some(handle) = open_process_handle(process_id) {
            if terminate_process(handle) {
                println!("Process terminated gracefully.");
            } else {
                println!("Failed to terminate the process.");
            }
            close_handle(handle);
        } else {
            println!("Failed to open process handle.");
        }
    } else {
        println!("Process not found.");
    }
}
fn win32_wmclose() {
    use std::ptr;
    use winapi::shared::windef::HWND;
    use winapi::um::winuser::{FindWindowA, SendMessageA};
    use winapi::um::winuser::{MessageBoxA, MB_OK, WM_CLOSE};
    // Replace "Notepad" with the title of the window you want to close
    let window_title = "*h - Notepad";

    // Find the window handle by its title
    let window_handle =
        unsafe { FindWindowA(ptr::null(), CString::new(window_title).unwrap().as_ptr()) };
    if window_handle.is_null() {
        // Window not found
        unsafe {
            MessageBoxA(
                ptr::null_mut(),
                CString::new("Window not found.").unwrap().as_ptr(),
                CString::new("Error").unwrap().as_ptr(),
                MB_OK,
            );
        }
        return;
    }

    // Send the WM_CLOSE message to the window
    let result = unsafe { SendMessageA(window_handle, WM_CLOSE, 0, 0) };
    if result == 0 {
        // Failed to send message
        unsafe {
            MessageBoxA(
                ptr::null_mut(),
                CString::new("Failed to send message.").unwrap().as_ptr(),
                CString::new("Error").unwrap().as_ptr(),
                MB_OK,
            );
        }
        return;
    }

    // Message successfully sent
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            CString::new("WM_CLOSE message sent.").unwrap().as_ptr(),
            CString::new("Success").unwrap().as_ptr(),
            MB_OK,
        );
    }
}

fn try_write() {
    // fs::write("ttt", b"\x03").expect("failed to write");
    let stdio_out = Stdio::from(File::create(format!("log_out.txt")).unwrap());
    let stdio_in = Stdio::from(File::create(format!("ttt")).unwrap());
    let mut child = Command::new("yes")
        // .stdout(stdio_out)
        // .stdin(stdio_in)
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let pid = child.id();
    std::thread::spawn(move || {
        sleep(Duration::from_millis(1000));
        unsafe {
            winapi::um::wincon::GenerateConsoleCtrlEvent(
                winapi::um::wincon::CTRL_C_EVENT,
                pid as u32,
            );
        }
        stdin
            .write_all("\x03".as_bytes())
            .expect("Failed to write to stdin");
        // stdin.write_all("Hello, world!".as_bytes()).expect("Failed to write to stdin");
    });
    child.wait().expect("?");
    // // let mut err_file = File::create(format!("log_err.txt", id)).unwrap();
    // err_file
    //     .write_all(
    //         format!(
    //             "AAAAAAAAAAAA\n\n",
    //         )
    //         .as_bytes(),
    //     )
    //     .expect("");
    // let stdio_err = Stdio::from(err_file);
}
