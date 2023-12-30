use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize)]
pub struct TrackerResponse {
    pub interval: usize,
    // Since this is a big binary mess, use the enum Value from bencode
    pub peers: serde_bencode::value::Value,

}

impl TrackerResponse {
    pub fn get_peers(&self) -> Vec<String> {
        let received_peer_data = &self.peers;
        let mut peers: Vec<String> = Vec::new();
        match received_peer_data {
            serde_bencode::value::Value::Bytes(bin_data) => {
                // Every 6 bytes is another address
                 for i in 0..(bin_data.len() / 6) {
                    let slice_end = 6 * (i+1);
                    let slice_start = slice_end-6;
                    let socket_bytes: &[u8] = &bin_data[slice_start..slice_end];
                    // Ipv4Addr's from trait implements a from method that takes [u8;4] 
                    let ip_bytes: [u8;4] = socket_bytes[0..4].try_into().unwrap();
                    let port_bytes: [u8;2] = socket_bytes[4..6].try_into().unwrap();
                    let ip_addr = Ipv4Addr::from(ip_bytes);
                    let port = u16::from_be_bytes(port_bytes);
                    let mut socket_string: String = String::new();
                    socket_string.push_str(ip_addr.to_string().as_str());
                    socket_string.push(':');
                    socket_string.push_str(port.to_string().as_str());
                    peers.push(socket_string);
                }
            },
            _ => panic!("Peer data should be a list of bytes")
        }
        peers
    }
}