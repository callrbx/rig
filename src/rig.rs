use std::env;
use structopt::StructOpt;

use librig;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "rig",
    author = "Drew Parker",
    about = "simple DNS lookup utility",
    long_about = "Fully featured DNS lookup utility, utilizing librig"
)]
struct Args {
    #[structopt(
        short = "s",
        long = "server",
        help = "server to perform lookups against <IP:port> (53 assumed if not set)"
    )]
    server: Option<String>,
    hostnames: Vec<String>,
}

fn main() {
    let args = Args::from_args();

    if env::args().len() < 2 {
        eprintln!("No hostname provided");
        std::process::exit(1);
    }

    let server: Option<String> = match args.server {
        Some(s) => {
            if !s.contains(":") {
                let mut server: String = String::from(s);
                server.push_str(":53");
                Some(server)
            } else {
                Some(s)
            }
        }
        None => None,
    };

    let num_domains = args.hostnames.len();

    if args.hostnames.len() >= 1 {
        for d in args.hostnames {
            librig::do_lookup(d, server.clone());
            if num_domains >= 2 {
                println!("");
            }
        }
    } else {
        eprintln!("No hostname provided");
    }
}
