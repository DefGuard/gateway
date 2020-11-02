use std::process::Command;

pub fn assign_addr(
    interface: &String,
    addr: &String,
) -> Result<std::process::ExitStatus, std::io::Error> {
    println!("{:?}", Command::new("whoami").output());
    // FIXME: don't use sudo
    let mut command = Command::new("sudo");
    command.args(&["ip", "addr", "add", addr, "dev", interface]);
    println!("{:?}", command);
    command.status()
}
