use crate::torrent::Torrent;

use crate::tracker::HandshakeMessage;

use std::net::{SocketAddrV4, TcpStream};
use std::io::{Write, Read};
use std::str::FromStr;
use std::io::{Error, ErrorKind};
use std::convert::From;
use sha1::{Digest, Sha1};

pub fn calculate_piece_hash(bytes: &Vec<u8>) -> String {
    let mut hash = Sha1::new();
    hash.update(bytes);
    let hashed_bytes: Vec<u8> = hash.finalize().to_vec();
    let piece_hash: String = hex::encode(hashed_bytes);
    piece_hash
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
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
        let length_bytes: [u8; 4] = self.length.to_be_bytes();

        byte_vector.extend_from_slice(&length_bytes);
        byte_vector.push(self.message_id as u8);
        byte_vector.append(&mut self.payload.clone());

        byte_vector
    }
}

#[derive(PartialEq)]
pub enum PeerStatus {
    PeerChoking,
    PeerInterested
}

#[derive(PartialEq)]
pub enum DownloaderStatus {
    DownloaderChoking,
    DownloaderInterested
}

pub struct Piece {
    pub index: usize,
    pub length: usize,
    pub hash: String,
    pub payload: Vec<u8>
}

impl Piece {
    pub fn new(idx: usize, len: usize) -> Self {
        Piece {
            index: idx,
            length: len,
            hash: String::new(),
            payload: Vec::with_capacity(len)
        }
    }
}

pub struct PeerDownloader {
    pub tcp_stream: TcpStream,
    pub peer_status: PeerStatus,
    pub downloader_status: DownloaderStatus,
}

impl PeerDownloader {
    pub fn new(socket_addr: &str) -> std::io::Result<Self> {
        let socket_address = SocketAddrV4::from_str(socket_addr).unwrap();
        // println!("{:?}", socket_address);
        Ok(PeerDownloader {
            tcp_stream: TcpStream::connect(socket_address)
                .expect(format!("Could Not Initiate Connection to {:?}", socket_addr).as_str()),
            peer_status: PeerStatus::PeerChoking,
            downloader_status: DownloaderStatus::DownloaderChoking
        })
    }

    // TODO: Error handle
    pub fn handshake(&mut self, torrent_data: &Torrent) -> Result<String, std::io::Error> {
        let info_hash: Vec<u8> = torrent_data.info.calculate_sha1_hash().1;
        let byte_array: [u8; 20] = {
            let mut arr = [0; 20]; // Initialize an array of zeros
            arr.copy_from_slice(&info_hash.as_slice()[..20]); // Copy data from slice to array
            arr
        };
        let handshake_msg: HandshakeMessage = HandshakeMessage::new(byte_array);
        // Create the TCP Stream
        self.tcp_stream.write(&handshake_msg.get_message_bytes())?;

        let mut response_container: [u8; 68] = [0; 68];
        self.tcp_stream.read_exact(&mut response_container)?;

        let peer_id = response_container[48..68].to_owned();
        // println!("Peer ID: {}", hex::encode(peer_id))
        Ok(hex::encode(peer_id))
    }

    pub fn read_peer_message(&mut self) -> Result<PeerMessage,std::io::Error>{
        // Read in the first 4 bytes to get message length
        let mut received_message_length: [u8; 4] = [0; 4];
        self.tcp_stream.read_exact(&mut received_message_length)?;

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
        if let Ok(b) = self.tcp_stream.write(&mut msg_bytes) {
            if message_length == b {
                return Ok(message_length);
            }
            else {
                return Err(std::io::Error::new(ErrorKind::WriteZero, "Did not write entire message to socket"));
            }
        }
        else {
            return Err(std::io::Error::new(ErrorKind::WriteZero, "Write to socket failed"));
        }
    }

    pub fn download_chunk(&mut self, piece_index: u32, chunk_offset: u32, chunk_size: u32) -> Result<Vec<u8>, std::io::Error> {
        const REQUEST_MSG_ID: MessageId = MessageId::Request;
        const REQUEST_MSG_LEN: u32 = 13;

        let mut request_payload: Vec<u8> = Vec::new();
        let index_byte_array: [u8; 4] = piece_index.to_be_bytes();
        let begin_byte_array: [u8; 4] = chunk_offset.to_be_bytes();
        let length_byte_array: [u8; 4] = chunk_size.to_be_bytes();

        request_payload.extend_from_slice(&index_byte_array);
        request_payload.extend_from_slice(&begin_byte_array);
        request_payload.extend_from_slice(&length_byte_array);

        let mut request_message_byte_array: Vec<u8> =
            PeerMessage::new(REQUEST_MSG_LEN, REQUEST_MSG_ID, &request_payload).get_message_bytes();

        match self.tcp_stream.write(&mut request_message_byte_array) {
            Ok(_b) => {
                // The piece payload has 2 u32 values: index, and begin, before the actual chunk data that we have to trim out
                let mut chunk_data = self.read_peer_message().unwrap();
                if chunk_data.message_id != MessageId::Piece {
                    return Err(Error::new(ErrorKind::InvalidData, "Did Not Receive Chunk"));
                }
                // Drain the first 8 bytes
                let block: Vec<u8> = chunk_data.payload.drain(8..).into_iter().collect();
                Ok(block)
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    // TODO: Pipeline this (async)
    pub fn download_piece(&mut self, piece: &mut Piece, chunk_size: usize) -> Result<usize, std::io::Error> {
        if self.peer_status == PeerStatus::PeerChoking {
            return Err(Error::new(ErrorKind::ConnectionRefused, "Peer is Choking"));
        }
        // Calculate how many chunks we have to download
        let mut total_chunks: usize = piece.length / chunk_size;
        // If chunk size doesn't directly divide into piece size, download an extra chunk of a shorter size
        if piece.length % chunk_size > 0 {
            total_chunks += 1;
        }

        // let mut piece_obj: Piece = Piece::new(piece.index, piece.length);
        let mut final_chunk_size:usize = usize::MAX;
        for i in 0..total_chunks {
            let starting_offset: u32 = i as u32 * chunk_size as u32;
            // Make sure you still have enough data in the piece to download a whole chunk by checking to see
            // if the next full chunk size is bigger than number of bytes available
            if (i+1)*chunk_size > piece.length {
                final_chunk_size = piece.length - (i*chunk_size);
            }

            // If we're not downloading the last chunk, final chunk size will be usize max
            // so we set it to the default chunk size and pass that to the downloader
            if final_chunk_size > chunk_size {
                final_chunk_size = chunk_size;
            }
            piece.payload.append(&mut self.download_chunk(piece.index as u32, starting_offset, final_chunk_size as u32)?);
        }
        let hash = calculate_piece_hash(&piece.payload);
        piece.hash = hash;
        Ok(piece.payload.len())
    }
}