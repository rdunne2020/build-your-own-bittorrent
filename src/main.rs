#![allow(unused)]

mod torrent;
use torrent::Torrent;

mod tracker;
use tracker::TrackerResponse;
use tracker::HandshakeMessage;

mod downloads;
use downloads::PeerDownloader;
use downloads::PeerMessage;

use serde_json;
use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::str::FromStr;

use clap::{arg, Parser, Arg, Command};

fn write_piece_to_file(path: &String, piece_data: &Vec<u8>) -> std::io::Result<u32> {
    let mut piece_file_io: File = File::create(path)?;
    piece_file_io.write_all(piece_data)?;
    Ok(piece_data.len() as u32)
}

fn decode_bencoded_input(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next() {
        Some('d') => {
            let mut token_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            let mut dict_string = encoded_value.strip_prefix('d').unwrap();

            while !dict_string.is_empty() && !dict_string.starts_with('e') {
                let (key, val_and_rest) = decode_bencoded_input(dict_string);
                let (val, rest) = decode_bencoded_input(val_and_rest);

                let key = match key {
                    serde_json::Value::String(s) => {
                        s
                    }
                    _ => {
                        panic!("Dictionary Keys Must of Bencode Type String");
                    }
                };
                token_map.insert(key, val);
                dict_string = rest;
            }
            // Need to consume the final 'e' of the dict since it's left out
            return (token_map.into(), &dict_string[1..]);
        },
        Some('l') => {
            let mut token_list = Vec::new();
            let mut list_string = encoded_value.strip_prefix('l').unwrap();
            // Loop through each chunk until you find e
            while !list_string.is_empty() && !list_string.starts_with('e') {
                let (val_token, rest_of_str) = decode_bencoded_input(list_string);
                token_list.push(val_token);
                list_string = rest_of_str;
            }
            // Need to consume the final 'e' of the dict since it's left out
            return (serde_json::Value::Array(token_list), &list_string[1..]);
        },
        Some('i') => {
            // Split the string at the ending 'e'
            if let Some((int_string, rest_of_str)) = encoded_value.split_once('e') {
                // Strip the i out
                if let Some(trimmed_int_string) = int_string.strip_prefix('i') {
                    return (serde_json::Value::Number(serde_json::Number::from(i64::from_str_radix(&trimmed_int_string, 10).unwrap())), rest_of_str);
                }
            }
        },
        // Parse a string value
        Some('0'..='9') => {
            // Use if let block to get the string length, and the rest of the encoded string
            if let Some((str_len, return_string)) = encoded_value.split_once(':') {
                // Turn the string length into a usize for slicing
                if let Ok(string_length) = str_len.parse::<usize>() {
                    // Return a tuple with the actual string sliced out as 1st, and the rest of the string after the slice as second
                    return (return_string[..string_length].to_string().into(), &return_string[string_length..]);
                }
            }
        },
        _ => ()
    }
    panic!("Unhandled encoded value: {}", encoded_value)
}

fn read_torrent_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_decode() {
        let enc_str = "d3:foo3:bar5:helloi52ee";
        let (val, rest) = decode_bencoded_input(enc_str);

        assert_eq!(val, serde_json::json!({"foo": "bar", "hello": 52}));
    }

    #[test]
    fn test_list_decode() {
        let enc_str = "l5:helloi69ee";
        let (tokens, string) = decode_bencoded_input(enc_str);
        println!("{}",string);
        assert_eq!(tokens, serde_json::json!(["hello", 69]));
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() {

    let cmd = Command::new("rTorrent")
        .bin_name("rTorrent")
        .subcommand_required(true)
        .subcommand(Command::new("download_piece")
            .about("Download one specific piece of a file")
            .args(&[
                //arg!(-o <OUTPUT> "File to save the piece to"),
                Arg::new("output_file")
                .required(true)
                .short('o')
                .long("output")
                .help("File to save the piece to"),
                arg!(<torrentfile> "Torrent File to Read"),
                arg!(<piecenum> "Which Piece Number to Download")
            ])
    );

    let matches = cmd.get_matches();

    match matches.subcommand_name() {
        // If the command is download_piece
        Some("download_piece") => {
            let dl = matches.subcommand_matches("download_piece").unwrap();
            let output: &String = dl.get_one::<String>("output_file").expect("Need Output File passed in");
            let torrentfile: &String = dl.get_one::<String>("torrentfile").expect("Need torrent file passed in");
            let piecenum: u32 = dl.get_one::<String>("piecenum")
                .expect("Need piece number passed in")
                .parse::<u32>().unwrap();

            if let Ok(torrent_bytes) = read_torrent_file(PathBuf::from(torrentfile.as_str()).as_path()) {
                let mut torrent_data: Torrent = de::from_bytes::<Torrent>(&torrent_bytes).unwrap();
                let binary_tracker_info = torrent_data.get_tracker_info().await.unwrap().bytes().await.unwrap();
                let decoded_tracker_data: TrackerResponse =
                    serde_bencode::from_bytes(&binary_tracker_info.as_ref()).unwrap();
                let trackers: &Vec<String> = &decoded_tracker_data.get_peers();

                // Setup the DL helper, then handshake and start passing messages
                let mut dl_helper: PeerDownloader = PeerDownloader::new(trackers[1].as_str(), torrent_data.info.piece_length as usize);
                dl_helper.handshake(&torrent_data);
                let bitfield_msg = dl_helper.read_peer_message();

                let interested_message: PeerMessage = PeerMessage {
                    length: 1,
                    message_id: 2,
                    payload: vec![]
                };
                // Unchoke downloader
                dl_helper.downloader_status = downloads::DownloaderStatus::DownloaderInterested;
                // Send Interested Message
                dl_helper.send_peer_message(&interested_message);

                let unchoke_message = dl_helper.read_peer_message();
                // Once the unchoke message is received we can start requesting data
                dl_helper.peer_status = downloads::PeerStatus::PeerInterested;
                println!("{}", unchoke_message.message_id);
                // Download 16k chunks (16384 bytes)
                let piece = dl_helper.download_piece(piecenum, torrent_data.info.piece_length as usize, 16384);
                println!("Downloaded piece of length: {}", piece.len());

                println!("Wrote piece {} to file: {} (Size {})",
                    piecenum, output, write_piece_to_file(output, &piece).unwrap());
            }
            else {
                println!("Failed to Read Torrent File");
            }
        }
        _ => ()
    }

    // let args: Vec<String> = env::args().collect();
    // let command = &args[1];

    // if command == "decode" {
    //    // Uncomment this block to pass the first stage
    //    let encoded_value = &args[2];
    //    let decoded_value = decode_bencoded_input(encoded_value).0;
    //    println!("{}", decoded_value.to_string());
    // }
    // else if command == "info" {
    //     let torrent_file_path = PathBuf::from(&args[2]);
    //     let torrent_data = read_torrent_file(torrent_file_path.as_path());
    //     let mut torrent_data: Torrent =
    //         match torrent_data {
    //             Ok(buf) => {
    //                 match de::from_bytes::<Torrent>(&buf) {
    //                     Ok(t) => t, //torrent_data = t,
    //                     Err(e) => panic!("{}", e)
    //                 }
    //             }
    //             Err(e) => panic!("{}", e)
    //         };
    //     println!("Tracker URL: {}\nLength: {}\nInfo Hash: {}", torrent_data.announce.clone().unwrap(), torrent_data.info.length, torrent_data.info.print_info_hash_hex());
    //     println!("Piece Length: {}", torrent_data.info.piece_length);
    //     println!("Piece Hashes:");
    //     for i in torrent_data.info.print_piece_hashes() {
    //         println!("{}", i);
    //     }
    // }
    // else if command == "peers" {
    //    // Uncomment this block to pass the first stage
    //     let torrent_file_path = PathBuf::from(&args[2]);
    //     let torrent_data = read_torrent_file(torrent_file_path.as_path());
    //     let mut torrent_data: Torrent =
    //         match torrent_data {
    //             Ok(buf) => {
    //                 match de::from_bytes::<Torrent>(&buf) {
    //                     Ok(t) => t, //torrent_data = t,
    //                     Err(e) => panic!("{}", e)
    //                 }
    //             }
    //             Err(e) => panic!("{}", e)
    //         };
    //     let bin_data = torrent_data.get_tracker_info().await.unwrap().bytes().await.unwrap();
    //     let decoded_data: TrackerResponse = serde_bencode::from_bytes(bin_data.as_ref()).unwrap();
    //     for ip in decoded_data.get_peers() {
    //         println!("{}", ip);
    //     }
    // }
    // else if command == "handshake" {
    //     let torrent_file_path = PathBuf::from(&args[2]);
    //     let torrent_data = read_torrent_file(torrent_file_path.as_path());
    //     let mut torrent_data: Torrent =
    //         match torrent_data {
    //             Ok(buf) => {
    //                 match serde_bencode::de::from_bytes::<Torrent>(&buf) {
    //                     Ok(t) => t, //torrent_data = t,
    //                     Err(e) => panic!("{}", e)
    //                 }
    //             }
    //             Err(e) => panic!("{}", e)
    //         };
    //     let socket_str = &args[3];
    //     let socket_obj = SocketAddrV4::from_str(&socket_str.as_str());
    //     match socket_obj {
    //         Ok(sock) => {
    //             let info_hash = torrent_data.info.calculate_sha1_hash().1;
    //             let byte_array: [u8; 20] = {
    //                 let mut arr = [0; 20]; // Initialize an array of zeros
    //                 arr.copy_from_slice(&info_hash.as_slice()[..20]); // Copy data from slice to array
    //                 arr
    //             };
    //             let handshake_msg: HandshakeMessage = HandshakeMessage::new(byte_array);
    //             // Create the TCP Stream
    //             let mut stream = TcpStream::connect(sock).expect(format!("Could Not Initiate Connection to {:?}", sock).as_str());
    //             stream.write_all(&handshake_msg.get_message_bytes());

    //             let mut response_container: [u8; 68] = [0; 68];
    //             stream.read_exact(&mut response_container);

    //             let peer_id = response_container[48..68].to_owned();
    //             println!("Peer ID: {}", hex::encode(peer_id))
    //         },
    //         Err(e) => println!("{:?}", e)
    //     };
    // }
    // else {
    //    println!("unknown command: {}", args[1])
    // }
}
