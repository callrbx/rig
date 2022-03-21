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

    // parse DNS server
    // if set in args, use that one
    // otherwise, parse /etc/resolv.conf and find the nameserver
    // append ports in either case
    let mut nameserver: String = match args.server {
        Some(ns) => ns,
        None => librig::parse_resolvconf_nameserver(None),
    };

    // add specified port to the namserver
    if !nameserver.contains(":") {
        nameserver.push_str(":53");
    }

    let num_domains = args.hostnames.len();
    let mut done_domains = 0;

    if args.hostnames.len() >= 1 {
        for d in args.hostnames {
            librig::do_lookup(d, nameserver.clone());
            done_domains += 1;
            if done_domains < num_domains {
                println!("");
            }
        }
    } else {
        eprintln!("No hostname provided");
    }
}
