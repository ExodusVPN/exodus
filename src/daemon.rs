

use std::process::Command;
use std::env;

fn worker() {
    loop {
        // do something ...
    }
}

fn main() {
    let mut args = env::args();
    let executable = args.next().unwrap();
    
    println!("executable: {:?}", executable);
    match args.next() {
        Some(sub_command) => match sub_command.as_str() {
            "daemon" => {
                let child = Command::new(executable)
                                    .spawn()
                                    .expect("Child process failed to start.");
                let pid = child.id();
                println!("child pid: {}", pid);
            },
            _ => {
                println!("Usage: \n\t$ ./test \n\t$ ./test daemon");
            }
        },
        None => {
            println!("This is an incredibly simple daemon!");
            worker();
        }
    }
}

