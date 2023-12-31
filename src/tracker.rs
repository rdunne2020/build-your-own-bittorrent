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

pub struct HandshakeMessage {
    pub length: u8,
    pub protocol: String,
    pub zeros: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: String,
}

impl HandshakeMessage {
    pub fn new(hash: [u8; 20]) -> Self {
        HandshakeMessage {
            length: 19,
            protocol: String::from("BitTorrent protocol"),
            zeros: [0; 8],
            info_hash: hash,
            peer_id: String::from("13376942013376942069")
        }
    }
    pub fn get_message_bytes(&self) -> [u8; 68] {
        let protocol_string_to_bytes = self.protocol.as_bytes();
        let peer_id_to_bytes = self.peer_id.as_bytes();

        let mut message_byte_vec: Vec<u8> = Vec::new();
        message_byte_vec.push(self.length);
        message_byte_vec.append(&mut protocol_string_to_bytes.to_owned());
        for b in self.zeros {
            message_byte_vec.push(b);
        }
        for b in self.info_hash {
            message_byte_vec.push(b)
        }

        message_byte_vec.append(&mut peer_id_to_bytes.to_owned());
        let byte_array: [u8; 68] = {
            let mut arr = [0; 68]; // Initialize an array of zeros
            arr.copy_from_slice(&message_byte_vec.as_slice()[..68]); // Copy data from slice to array
            arr
        };
        byte_array
    }
}