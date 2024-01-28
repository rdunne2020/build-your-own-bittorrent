use super::torrent::Torrent;

use super::tracker::HandshakeMessage;

use std::net::{SocketAddrV4, TcpStream};
use std::io::{Write, Read};
use std::str::FromStr;
use std::io::{Error, ErrorKind};
use std::convert::From;

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum MessageId {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
    Port = 9
}

impl From<u8> for MessageId {
    fn from(id: u8) -> Self {
        match id {
            0 => MessageId::Choke,
            1 => MessageId::Unchoke,
            2 => MessageId::Interested,
            3 => MessageId::NotInterested,
            4 => MessageId::Have,
            5 => MessageId::Bitfield,
            6 => MessageId::Request,
            7 => MessageId::Piece,
            8 => MessageId::Cancel,
            9 => MessageId::Port,
            _ => MessageId::Choke
        }
    }
}

pub struct PeerMessage {
    pub length: u32,
    pub message_id: MessageId,
    pub payload: Vec<u8>
}

impl PeerMessage {
    pub fn new(length: u32, id: MessageId, data: &Vec<u8>) -> Self {
        PeerMessage {
            length,
            message_id: id,
            payload: data.clone()
        }
    }
    pub fn get_message_bytes(&self) -> Vec<u8> {
        let mut byte_vector: Vec<u8> = vec![];
        let mut length_bytes: [u8; 4] = self.length.to_be_bytes();

        byte_vector.extend_from_slice(&length_bytes);
        byte_vector.push(self.message_id as u8);
        byte_vector.append(&mut self.payload.clone());

        byte_vector
    }
}

pub enum PeerStatus {
    PeerChoking,
    PeerInterested
}

pub enum DownloaderStatus {
    DownloaderChoking,
    DownloaderInterested
}

pub struct PeerDownloader {
    tcp_stream: TcpStream,
    pub peer_status: PeerStatus,
    pub downloader_status: DownloaderStatus,
    piece_size: usize,
    block_size_multiplier: usize
}

impl PeerDownloader {
    pub fn new(socket_addr: &str, piece_length: usize) -> Self {
        let socket_address = SocketAddrV4::from_str(socket_addr).unwrap();
        println!("{:?}", socket_address);
        PeerDownloader {
            tcp_stream: TcpStream::connect(socket_address)
                .expect(format!("Could Not Initiate Connection to {:?}", socket_addr).as_str()),
            peer_status: PeerStatus::PeerChoking,
            downloader_status: DownloaderStatus::DownloaderChoking,
            piece_size: piece_length,
            block_size_multiplier: 1024
        }
    }

    // TODO take a vector of peer sockets to connect to
    pub fn handshake(&mut self, torrent_data: &Torrent) {
        let info_hash: Vec<u8> = torrent_data.info.calculate_sha1_hash().1;
        let byte_array: [u8; 20] = {
            let mut arr = [0; 20]; // Initialize an array of zeros
            arr.copy_from_slice(&info_hash.as_slice()[..20]); // Copy data from slice to array
            arr
        };
        let handshake_msg: HandshakeMessage = HandshakeMessage::new(byte_array);
        // Create the TCP Stream
        self.tcp_stream.write_all(&handshake_msg.get_message_bytes());

        let mut response_container: [u8; 68] = [0; 68];
        self.tcp_stream.read_exact(&mut response_container);

        let peer_id = response_container[48..68].to_owned();
        println!("Peer ID: {}", hex::encode(peer_id))
    }

    // TODO: Make this an Option, need better error handling in general
    pub fn read_peer_message(&mut self) -> Result<PeerMessage,std::io::Error>{
        // Read in the first 4 bytes to get message length
        let mut received_message_length: [u8; 4] = [0; 4];
        self.tcp_stream.read_exact(&mut received_message_length);

        // Store length in a u32
        let message_len: u32 = u32::from_be_bytes(received_message_length);
        let mut received_message_body: Vec<u8> = vec![0; message_len as usize];
        let read_status = self.tcp_stream.read_exact(&mut received_message_body);

        match read_status {
            Ok(()) => {
                let msg_id: u8 = received_message_body[0];

                let payload: Vec<u8> = received_message_body.drain(1..).into_iter().collect();

                // Return the message
                Ok(PeerMessage {
                    length: message_len,
                    message_id: MessageId::from(msg_id),
                    payload
                })
            },
            Err(e) => {
                return Err(e);
            }
        }
        // Now Split the first byte of the body out to get message ID, then store the rest as the body
    }

    pub fn send_peer_message(&mut self, peer_msg: &PeerMessage) -> Result<usize, std::io::Error> {
        let mut msg_bytes: Vec<u8> = peer_msg.get_message_bytes();
        let message_length: usize = msg_bytes.len();
        // Send Message
        if let Ok(()) = self.tcp_stream.write_all(&mut msg_bytes) {
            return Ok(message_length);
        }
        else {
            return Err(std::io::Error::new(ErrorKind::WriteZero, "Write to socket failed"));
        }
    }

    pub fn download_chunk(&mut self, piece_index: u32, chunk_offset: u32, chunk_size: u32) -> Option<Vec<u8>> {
        const REQUEST_MSG_ID: MessageId = MessageId::Request;
        const REQUEST_MSG_LEN: u32 = 13;

        let mut request_message_byte_array: Vec<u8> = Vec::new();
        let mut request_payload: Vec<u8> = Vec::new();
        let mut index_byte_array: [u8; 4] = piece_index.to_be_bytes();
        let mut begin_byte_array: [u8; 4] = chunk_offset.to_be_bytes();
        let mut length_byte_array: [u8; 4] = chunk_size.to_be_bytes();

        request_payload.extend_from_slice(&index_byte_array);
        request_payload.extend_from_slice(&begin_byte_array);
        request_payload.extend_from_slice(&length_byte_array);

        request_message_byte_array= PeerMessage::new(REQUEST_MSG_LEN, REQUEST_MSG_ID, &request_payload).get_message_bytes();

        if let Ok(()) = self.tcp_stream.write_all(&mut request_message_byte_array) {
            // The piece payload has 2 u32 values: index, and begin, before the actual chunk data that we have to trim out
            let mut chunk_data = self.read_peer_message().unwrap();
            // Drain the first 8 bytes
            let block: Vec<u8> = chunk_data.payload.drain(8..).into_iter().collect();
            Some(block)
        }
        else {
            None
        }
    }

    // TODO: Pipeline this (async)
    pub fn download_piece(&mut self, piece_index: u32, piece_size: usize, chunk_size: usize) -> Vec<u8> {
        // Calculate how many chunks we have to download
        let mut total_chunks: usize = piece_size / chunk_size;
        // If chunk size doesn't directly divide into piece size, download an extra chunk of a shorter size
        if piece_size % chunk_size > 0 {
            total_chunks += 1;
        }

        let mut piece_data: Vec<u8> = Vec::new();
        let mut downloaded_bytes: usize = 0;
        let mut final_chunk_size:usize = usize::MAX;
        for i in 0..total_chunks {
            let starting_offset: u32 = i as u32 * chunk_size as u32;
            // Make sure you still have enough data in the piece to download a whole chunk by checking to see
            // if the next full chunk size download will be more bytes than are available
            if downloaded_bytes + chunk_size > piece_size {
                final_chunk_size = (chunk_size - (piece_size - downloaded_bytes));
            }

            // If we're not downloading the last chunk, final chunk size will be usize max
            // so we set it to the default chunk size and pass that to the downloader
            if final_chunk_size > chunk_size {
                final_chunk_size = chunk_size;
            }
            println!("Downloading Chunk: {}", i);
            if let Some(mut chunk_data) = self.download_chunk(piece_index, starting_offset, final_chunk_size as u32) {
                // Update downloaded_bytes
                downloaded_bytes += chunk_data.len();
                // Store the payload data into our final vector
                piece_data.append(&mut chunk_data);

                println!("Downloaded Chunk: {}", i);
            }
            // Sending request failed
            else {
                return vec![];
            }
        }
        piece_data
    }
}
