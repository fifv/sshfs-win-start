fn main() {
    let pid = 58384;
    unsafe {
        let result = winapi::um::wincon::GenerateConsoleCtrlEvent(
            winapi::um::wincon::CTRL_BREAK_EVENT,
            pid,
        );
        println!("* ctrlc to {}, result: {}", pid, result);
    }
}