use std::sync::Arc;

use hyperwire::clock::SystemClock;
use hyperwire::{Server, Tun};

fn main() {
    println!("Listening on tun0 …");
    let device = Box::new(Tun::new("tun0").expect("failed to open tun0"));
    let clock = Arc::new(SystemClock);
    let mut server = Server::new(device, clock);
    server.run();
}
