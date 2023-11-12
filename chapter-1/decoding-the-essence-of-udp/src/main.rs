use socket2::{Domain, Protocol, Socket, Type};
use std::io::Result;
use std::mem::MaybeUninit;
use std::net::SocketAddr;

fn main() -> Result<()> {
    // Define the host to listen on
    let host: SocketAddr = "0.0.0.0:12345".parse().unwrap();

    // Create a raw socket, bind to the public interface
    let socket_protocol = if cfg!(target_os = "windows") { 0 } else { 1 };

    let sniffer = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(socket_protocol)),
    )?;

    sniffer.bind(&host.into())?;

    // Read one packet
    let mut buffer: [MaybeUninit<u8>; 65535] = unsafe { MaybeUninit::uninit().assume_init() };
    let _ = sniffer.recv_from(&mut buffer)?;
    let raw_buffer: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len()) };

    // Print the first 120 bytes of the captured packet
    println!("{:?}", &raw_buffer[..120]);

    Ok(())
}
