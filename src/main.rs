#![allow(unused)]

mod torrent;
use torrent::Torrent;

mod tracker;
use tracker::{TrackerResponse,HandshakeMessage};

mod downloads;
use downloads::{PeerDownloader,PeerMessage, Piece};

use serde_json;
use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::str::FromStr;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{SystemTime, Instant, UNIX_EPOCH};
use std::cell::RefCell;
use clap::{arg, Parser, Arg, Command};
use tokio::time::{sleep, Duration};
use sha1::{Digest, Sha1};

fn write_piece_to_file(path: &String, piece_data: &Piece) -> std::io::Result<u32> {
    let mut piece_file_io: File = File::create(path)?;
    piece_file_io.write_all(&piece_data.payload)?;
    Ok(piece_data.payload.len() as u32)
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

fn merge_tmp_files(output_path: &Path, tmp_files: &Vec<String>) -> std::io::Result<usize> {
    let mut downloaded_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(output_path)?;
    let mut written_bytes: usize = 0;
    for t in tmp_files {
        let mut file = OpenOptions::new().read(true).open(t.as_str())?;
        let mut contents: Vec<u8> = Vec::new();
        file.read_to_end(&mut contents);
        written_bytes += downloaded_file.write(&contents)?;
        // Close the file stream so we can remove the file from the tmp directory
        drop(file);
        std::fs::remove_file(t.as_str());
    }
    Ok(written_bytes)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() ->Result<(), std::io::Error>{

    let cmd = Command::new("rTorrent")
        .bin_name("rTorrent")
        .subcommand_required(true)
        .subcommand(Command::new("decode")
            .about("Decode bencode string")
            .arg(arg!(<BENCODEDSTRING>))
        )
        .subcommand(Command::new("info")
            .about("Parse Torrent File")
            .arg(arg!(<TORRENTFILE>))
        )
        .subcommand(Command::new("peers")
            .about("Get Peer Info from Tracker")
            .arg(arg!(<TORRENTFILE>))
        )
        .subcommand(Command::new("handshake")
            .about("Get Peer Info from Tracker")
            .arg(arg!(<TORRENTFILE>))
            .arg(arg!(<PEERSOCKET>))
        )
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
        )
        // TODO: We should get the filename from the torrent, so this should be optional
        .subcommand(Command::new("download")
            .about("Download the file")
            .args(&[
                Arg::new("output_file")
                .required(false)
                .short('o')
                .long("output")
                .help("File that will be saved"),
                Arg::new("download_dir")
                .required(false)
                .short('d')
                .long("directory")
                .help("Directory that the file will be saved to, this will be ignored if you utilize the -o flag"),
                arg!(<torrentfile> "Torrent File to Read")
            ])
        );

    let matches = cmd.get_matches();

    match matches.subcommand_name() {
        Some("decode") => {
            let cmd = matches.subcommand_matches("decode").unwrap();
            let encoded_val: &String = cmd.get_one::<String>("BENCODEDSTRING").expect("Need bencoded string as arg");
            let decoded_value = decode_bencoded_input(encoded_val).0;
            println!("{}", decoded_value.to_string());

        },
        Some("info") => {
            let cmd = matches.subcommand_matches("info").unwrap();
            let torrent_file_path: &String = cmd.get_one::<String>("TORRENTFILE").expect("Need path to torrentfile");
            let torrent_data = read_torrent_file(PathBuf::from(torrent_file_path.as_str()).as_path());
            let mut torrent_data: Torrent =
                match torrent_data {
                    Ok(buf) => {
                        match de::from_bytes::<Torrent>(&buf) {
                            Ok(t) => t, //torrent_data = t,
                            Err(e) => panic!("{}", e)
                        }
                    }
                    Err(e) => panic!("{}", e)
                };
            println!("Tracker URL: {}\nLength: {}\nInfo Hash: {}", torrent_data.announce.clone().unwrap(), torrent_data.info.length, torrent_data.info.print_info_hash_hex());
            println!("Piece Length: {}", torrent_data.info.piece_length);
            println!("Piece Hashes:");
            for i in torrent_data.info.return_piece_hashes() {
                println!("{}", i);
            }
        },
        Some("peers") => {
            let cmd = matches.subcommand_matches("peers").unwrap();
            let torrent_file_path: &String = cmd.get_one::<String>("TORRENTFILE").expect("Need path to torrentfile");
            let torrent_file_data = read_torrent_file(PathBuf::from(torrent_file_path.as_str()).as_path());
            let mut torrent_data: Torrent =
                match torrent_file_data {
                    Ok(buf) => {
                        match de::from_bytes::<Torrent>(&buf) {
                            Ok(t) => t, //torrent_data = t,
                            Err(e) => panic!("{}", e)
                        }
                    }
                    Err(e) => panic!("{}", e)
                };
            let bin_data = torrent_data.get_tracker_info().await.unwrap().bytes().await.unwrap();
            let decoded_data: TrackerResponse = serde_bencode::from_bytes(bin_data.as_ref()).unwrap();
            for ip in decoded_data.get_peers() {
                println!("{}", ip);
            }
        },
        Some("handshake") => {
            let cmd = matches.subcommand_matches("handshake").unwrap();
            let torrent_file_path: &String = cmd.get_one::<String>("TORRENTFILE").expect("Need path to torrentfile");
            let peer_socket: &String = cmd.get_one::<String>("PEERSOCKET").expect("Need socket addr:port for peer");
            let torrent_file_data = read_torrent_file(PathBuf::from(torrent_file_path.as_str()).as_path());
            let mut torrent_data: Torrent =
                match torrent_file_data {
                    Ok(buf) => {
                        match de::from_bytes::<Torrent>(&buf) {
                            Ok(t) => t, //torrent_data = t,
                            Err(e) => panic!("{}", e)
                        }
                    }
                    Err(e) => panic!("{}", e)
            };
            let mut dl_helper: Result<PeerDownloader, std::io::Error> =
                PeerDownloader::new(peer_socket.as_str());
            match dl_helper {
                Ok(mut downloader) => downloader.handshake(&torrent_data),
                Err(e) => {
                    panic!("Could not establish connection with peer")
                }
            };
        },
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
                let mut dl_helper: PeerDownloader = 
                    PeerDownloader::new(trackers[1].as_str()).expect("Could not connect to peer");
                dl_helper.handshake(&torrent_data);
                let bitfield_msg = dl_helper.read_peer_message();

                let interested_message: PeerMessage = PeerMessage {
                    length: 1,
                    message_id: downloads::MessageId::from(2),
                    payload: vec![]
                };
                // Unchoke downloader
                dl_helper.downloader_status = downloads::DownloaderStatus::DownloaderInterested;
                // Send Interested Message
                dl_helper.send_peer_message(&interested_message);

                let unchoke_message = dl_helper.read_peer_message();
                // Once the unchoke message is received we can start requesting data
                dl_helper.peer_status = downloads::PeerStatus::PeerInterested;
                // If we're downloading the very last piece we need a smaller piece size than usual
                // So we calculate here if we're getting the last piece and update piece size accordingly
                if (piecenum+1) as i64 * torrent_data.info.piece_length <= torrent_data.info.length {
                    // Download 16k chunks (16384 bytes)
                    let piece = 
                        dl_helper.download_piece(piecenum, torrent_data.info.piece_length as usize, 16384)?;
                    println!("Wrote piece {} to file: {} (Size {})",
                        piecenum, output, write_piece_to_file(output, &piece).unwrap());
                }
                else {
                    let new_piece_size = torrent_data.info.length - torrent_data.info.piece_length * (piecenum) as i64;
                    // Download 16k chunks (16384 bytes)
                    let piece = 
                        dl_helper.download_piece(piecenum, new_piece_size as usize, 16384)?;
                    println!("Wrote piece {} to file: {} (Size {})",
                        piecenum, output, write_piece_to_file(output, &piece).unwrap());
                }

            }
            else {
                println!("Failed to Read Torrent File");
            }
        },
        Some("download") => {
            const CHUNK_SIZE:usize = 16384;
            let dl = matches.subcommand_matches("download").unwrap();
            let torrentfile: &String = dl.get_one::<String>("torrentfile")
                .expect("Need torrent file passed in");

            // Read and parse the torrent file, if it's valid exchange data with the tracker
            let mut torrent_data: Torrent = de::from_bytes::<Torrent>(
                &read_torrent_file(PathBuf::from(torrentfile.as_str()).as_path())?
            ).unwrap();
            // Get output file, either from the --output flag or from the torrent file
            let mut downloaded_file_name = String::new();
            let mut downloaded_file_directory = String::new();
            let mut download_path = PathBuf::new();
            if let Some(output_file_flag) = dl.get_one::<String>("output_file") {
                downloaded_file_name = output_file_flag.clone();
                download_path = PathBuf::from(&downloaded_file_name);
            }
            else {
                downloaded_file_name = torrent_data.info.name.clone();
                if let Some(output_directory) = dl.get_one::<String>("download_dir") {
                    downloaded_file_directory = output_directory.clone();
                    download_path.push(&downloaded_file_directory);
                    download_path.push(&downloaded_file_name);
                }
                else {
                    download_path.push("./");
                    download_path.push(&downloaded_file_name);
                }
            }
            let binary_tracker_info = torrent_data.get_tracker_info().await.unwrap().bytes().await.unwrap();
            let decoded_tracker_data: TrackerResponse = serde_bencode::from_bytes(&binary_tracker_info.as_ref()).unwrap();
            let peers: &Vec<String> = &decoded_tracker_data.get_peers();
            let mut valid_peer_downloaders: Vec<Rc<RefCell<PeerDownloader>>> = Vec::new();
            // Make connection with each peer, keep each open until the file is done downloading
            // If the connection to one fails, just keep moving
            print!("Connecting to Peers...");
            for p in peers {
                let mut download_client = PeerDownloader::new(p.as_str());
                match download_client {
                    Ok(mut dl) => {
                        // Set the read timeout to half a second so a host doesn't spin forever
                        dl.tcp_stream.set_read_timeout(Some(Duration::from_millis(500)));
                        // Initiate the connection with a handshake and sharing of necessary messages
                        dl.handshake(&torrent_data);
                        /// TODO: Parse the bitfield message to get pieces
                        let bitfield_message = dl.read_peer_message();
                        let interested_message: PeerMessage = PeerMessage {
                            length: 1,
                            message_id: downloads::MessageId::from(2),
                            payload: vec![]
                        };
                        // Unchoke downloader
                        dl.downloader_status = downloads::DownloaderStatus::DownloaderInterested;
                        // Send Interested Message
                        dl.send_peer_message(&interested_message);

                        // Once the unchoke message is received we can start requesting data
                        // It can time out, in that case we know we are choked
                        if let Ok(unchoke_message) = dl.read_peer_message() {
                            if unchoke_message.message_id == downloads::MessageId::Unchoke {
                                dl.peer_status = downloads::PeerStatus::PeerInterested;
                            }
                        }
                        else {
                            dl.peer_status = downloads::PeerStatus::PeerChoking;
                        }

                        valid_peer_downloaders.push(Rc::new(RefCell::new(dl)));
                        print!("{:?} ", p.as_str());
                    }
                    Err(e) => {
                        println!("Failed To Connect to Peer: {} with error message: {}", p, e.to_string());
                    }
                }
            }
            println!("Connected!");
            // If no peer is available, error out
            if valid_peer_downloaders.len() < 1 {
                panic!("FATAL: Could Not Connect to any available peers, please check network connection and try again");
            }
            // TODO: This is insanity, should just have a vector of piece indices, then we pop and push them
            // Create a queue of pieces to request that can grow/shrink in size
            // It will store tuples of variant (usize, String, &mut PeerDownloader, Option<String>) that will keep
            // piece length, piece_index, piece hash, the download helper for the peer, and an option representing whether or not it successfully downloaded
            let mut piece_requests: VecDeque<(usize, usize, String, Rc<RefCell<PeerDownloader>>, Option<String>)> = VecDeque::new();
            let piece_hashes = torrent_data.info.return_piece_hashes();
            for (idx, hash) in piece_hashes.iter().enumerate() {
                // If you're downloading the last piece and file size isn't divisible by piece size, you have to download a smaller piece
                let mut piece_size = torrent_data.info.piece_length;
                if idx == piece_hashes.len()-1 && torrent_data.info.length % torrent_data.info.piece_length > 0 {
                    // The updated piece size is the length of the file minus the amount downloaded
                    // This isn't working
                    piece_size = torrent_data.info.length - torrent_data.info.piece_length * (idx) as i64;
                }
                // Arbitrarily choose which connection to download from
                let dl_client_ptr =
                    Rc::clone(valid_peer_downloaders.get(idx % valid_peer_downloaders.len()).unwrap());
                let mut piece_encapsulation =
                    (piece_size as usize, idx, hash.clone(), dl_client_ptr, None::<String>);
                piece_requests.push_back(piece_encapsulation);
            }
            let mut tmp_file_paths: Vec<String> = Vec::new();
            let mut index: usize = 0;
            let num_pieces: usize = piece_requests.len();
            // Management Loop
            // While there are any pieces that have not been downloaded keep looping
            let start = Instant::now();
            while piece_requests.iter().any(|a| a.4.is_none()) {
                let mut piece_info = piece_requests.get_mut(index).unwrap();
                // The current piece has already been downloaded skip it
                if piece_info.4.is_some() {
                    index += 1;
                    if index >= num_pieces {
                        index = 0;
                    }
                    continue;
                }
                let mut downloader = piece_info.3.borrow_mut();
                match downloader.download_piece(piece_info.1 as u32, piece_info.0, CHUNK_SIZE) {
                    // The piece download was successful, check hash and make sure data is valid, then write it to a tmp file
                    Ok(piece) => {
                        // Verify the hash is correct before saving the file
                        if &piece.hash == piece_hashes.get(index).unwrap() {
                            // Store the tmp file path that we're writing the piece to into the vector
                            let tmp_path = format!("/tmp/file.{}", index);
                            // Load the path we're writing to into the Option stored in the piece tuple so that we know it's done
                            piece_info.4 = Some(tmp_path.clone());
                            write_piece_to_file(&tmp_path, &piece);
                            tmp_file_paths.push(tmp_path);
                        }
                        else {
                            // TODO: Download this piece from another peer now
                            println!("Hash for piece {} is incorrect, {} != {}", index, piece.hash, piece_hashes.get(index).unwrap());
                        }
                    }
                    Err(e) => {
                        ()
                    }
                }
                // Increase the index or reset it
                if index >= num_pieces - 1 {
                    index = 0;
                    // If you've tried to download every piece, sleep for 100ms before attempting to download again
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                else {
                    index += 1;
                }
            }
            let duration = start.elapsed();
            println!("The time it took to download file was: {:?}", duration);

            // Now that we've downloaded all the pieces, merge them and we're done
            println!("Completed file: {} of size: {} bytes!", downloaded_file_name, merge_tmp_files(download_path.as_path(), &tmp_file_paths)?);
        },
        _ => ()
    }
    Ok(())
}
