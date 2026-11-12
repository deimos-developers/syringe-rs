//! Show how the loader separates its own flags from game arguments.

use syringe_rs::support::parse_command_line;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_command_line(&args) {
        Ok(command) => {
            println!("executable: {}", command.executable_name);
            println!("loader flags: {:?}", command.syringe_arguments);
            println!("game arguments: {}", command.game_arguments);
        }
        Err(error) => {
            eprintln!("{error}");
            println!("usage: command_line <exe> [-i=dll] [--detach] [--args=...]");
            std::process::exit(2);
        }
    }
}
