use std::env;

use librig;

fn main() {
    if env::args().len() < 2 {
        eprintln!("No hostname provided");
        std::process::exit(1);
    }

    let hostname = env::args().nth_back(0);

    match hostname {
        Some(d) => librig::do_lookup(d),
        None => eprintln!("No hostname provided"),
    }
}
