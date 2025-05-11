use fribra::{Server, Tun};

fn main() {
    println!("Listening on tun0 …");
    let device = Box::new(Tun::new("tun0").expect("failed to open tun0"));
    let mut server = Server::new(device);
    server.run();
}
