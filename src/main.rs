#![allow(unused)]

use reqwest::Response;
use serde_json;
use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{self, Read};
use sha1::{Digest, Sha1};
use std::collections::HashMap;

#[allow(dead_code)]

fn urlencode_binary_data(hash: &Vec<u8>) -> String {
    let mut encoded_string = String::with_capacity(hash.len()*3);
    for c in hash {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':'| b'?'| b'['| b']'| b'@'| b'!'| b'\''| b'('| b')'| b'*'| b','| b';'| b'='=> {
                // encoded_string.push_str(&format!("{c:02x}"));
                encoded_string.push(*c as char);
            }
            _ => {
                encoded_string.push('%');
                encoded_string.push_str(&format!("{c:02x}"));
            }
        }
    }
    println!("Encoded String: {}", encoded_string);
    encoded_string
}

#[derive(Debug, Deserialize,Serialize)]
struct TorrentInfo {
    pub length: i64,
    pub name: String,
    // Need this or the parse fails because the key value in the torrent file is "piece length", but serde can't find a matching key value in the struct
    #[serde(rename="piece length")]
    pub piece_length: i64,
    pub pieces: ByteBuf, 
}

impl TorrentInfo {
    fn calculate_sha1_hash(&self) -> String {
        let mut hash = Sha1::new();
        // hash.update(format!("{:?}", serde_bencode::to_bytes(self).unwrap()));
        hash.update(serde_bencode::to_bytes(self).unwrap());
        let result = hash.finalize();

        println!("{:?}", result);
        // Return hex string
        return result.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    }
    fn print_piece_hashes(&self) -> Vec<String>{
        // Each hash is 20 bytes
        let hash_string_size = 20;
        let bytes = self.pieces.to_vec();
        let num_pieces = bytes.len() / hash_string_size;
        let mut hash_strings: Vec<String> = Vec::new();
        for i in 0..num_pieces {
            let slice_start = i * 20;
            let slice_end = 20 * (i+1);
            let byte_slice: &[u8] = &bytes[slice_start..slice_end];
            hash_strings.push(byte_slice.iter().map(|c| format!("{:02x}", c)).collect::<String>());
        }
        hash_strings
    }
}

#[derive(Debug, Deserialize)]
struct Torrent {
    info: TorrentInfo,
    #[serde(default)]
    announce: Option<String>,
    #[serde(rename="created by")]
    created_by: Option<String>,
}

impl Torrent {
    // Function to request tracker data
    async fn get_tracker_info(&self) -> Option<Response> {
        let num_pieces = (self.info.pieces.to_vec().len() / 20);
        let tracker_url = self.announce.clone().unwrap();
        // println!("URL: {}", urlencode_binary_data(&serde_bencode::to_bytes(&self.info).unwrap()));
        // println!("Fart: {:?}", serde_urlencoded::to_string(&self.info));
        let mut param_map = HashMap::new();
        param_map.insert("info_hash".to_string(), urlencode_binary_data(&serde_bencode::to_bytes(&self.info).unwrap()));
        param_map.insert("peer_id".to_string(), "1337694201337694201".to_string());
        param_map.insert("port".to_string(), "6881".to_string());
        param_map.insert("uploaded".to_string(), "0".to_string());
        param_map.insert("downloaded".to_string(), "0".to_string());
        param_map.insert("length".to_string(), (num_pieces*(self.info.piece_length as usize)).to_string());
        param_map.insert("compact".to_string(), "1".to_string());

        // Make a request to the URL to get the info about it
        let tracker_response = reqwest::Client::new()
                                    .get(tracker_url)
                                    .query(&param_map)
                                    .send()
                                    .await;

        // println!("{:?}", tracker_response);
        Some(tracker_response.unwrap())
    }
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
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
       // Uncomment this block to pass the first stage
       let encoded_value = &args[2];
       let decoded_value = decode_bencoded_input(encoded_value).0;
       println!("{}", decoded_value.to_string());
    }
    else if command == "info" {
        let torrent_file_path = PathBuf::from(&args[2]);
        let torrent_data = read_torrent_file(torrent_file_path.as_path());
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
        println!("Tracker URL: {}\nLength: {}\nInfo Hash: {}", torrent_data.announce.clone().unwrap(), torrent_data.info.length, torrent_data.info.calculate_sha1_hash());
        println!("Piece Length: {}", torrent_data.info.piece_length);
        println!("Piece Hashes:");
        for i in torrent_data.info.print_piece_hashes() {
            println!("{}", i);
        }
        // TODO: Bad Info Hash
        println!("{:?}", torrent_data.get_tracker_info().await.unwrap().text().await);
    } else {
       println!("unknown command: {}", args[1])
    }
}
