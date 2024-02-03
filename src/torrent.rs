use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use reqwest::Response;


pub fn urlencode_binary_data(hash: &Vec<u8>) -> String {
    let mut encoded_string = String::with_capacity(hash.len()*3);
    for c in hash {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'?'| b'['| b']'| b'@'| b'!'| b'\''| b'('| b')'| b'*'| b','| b';'| b'='=> {
                encoded_string.push(*c as char);
            }
            _ => {
                encoded_string.push('%');
                encoded_string.push_str(&format!("{c:02X}"));
            }
        }
    }
    encoded_string
}

#[derive(Debug, Deserialize,Serialize)]
pub struct TorrentInfo {
    pub length: i64,
    pub name: String,
    // Need this or the parse fails because the key value in the torrent file is "piece length", but serde can't find a matching key value in the struct
    #[serde(rename="piece length")]
    pub piece_length: i64,
    pub pieces: ByteBuf, 
}

impl TorrentInfo {
    pub fn calculate_sha1_hash(&self) -> (String,Vec<u8>) {
        let mut hash = Sha1::new();
        hash.update(serde_bencode::to_bytes(self).unwrap());
        let result = hash.finalize();

        let hashed_bytes: Vec<u8> = result.to_vec();

        // Serialize the String to URL-encoded format
        let urlencoded_string = urlencode_binary_data(&hashed_bytes);

        // Return hex string
        return (urlencoded_string, hashed_bytes);

    }

    pub fn print_info_hash_hex(&self) -> String {
        let mut hash = Sha1::new();
        hash.update(serde_bencode::to_bytes(self).unwrap());
        let result = hash.finalize();

        let hashed_bytes: Vec<u8> = result.to_vec();

        hex::encode(result)
    }

    pub fn return_piece_hashes(&self) -> Vec<String>{
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
pub struct Torrent {
    pub info: TorrentInfo,
    #[serde(default)]
    pub announce: Option<String>,
    #[serde(rename="created by")]
    pub created_by: Option<String>,
}

impl Torrent {
    pub fn get_request_param_string(param_map: &HashMap<String, String>) -> String {
        let mut query_string: String = String::new();
        for (k,v) in param_map {
            query_string.push_str(k.as_str());
            query_string.push('=');
            query_string.push_str(v.as_str());
            query_string.push('&');
        }
        // Remove the last & added
        query_string.pop();
        query_string
    }
    // Function to request tracker data
    pub async fn get_tracker_info(&self) -> Option<Response> {
        let num_pieces = (self.info.pieces.to_vec().len() / 20);
        let tracker_url = self.announce.clone().unwrap();
        let info_hash = self.info.calculate_sha1_hash();
        let mut param_map = HashMap::new();

        param_map.insert("info_hash".to_string(), info_hash.0);
        param_map.insert("peer_id".to_string(), "13376942013376942069".to_string());
        param_map.insert("port".to_string(), "6881".to_string());
        param_map.insert("uploaded".to_string(), "0".to_string());
        param_map.insert("downloaded".to_string(), "0".to_string());
        param_map.insert("left".to_string(), self.info.length.to_string());
        param_map.insert("length".to_string(), (num_pieces*(self.info.piece_length as usize)).to_string());
        param_map.insert("compact".to_string(), "1".to_string());

        let param_string = Self::get_request_param_string(&param_map);
        let mut url = reqwest::Url::parse(&tracker_url).unwrap();
        url.set_query(Some(&param_string));
        let tracker_response = reqwest::Client::new().get(url).send().await;

        Some(tracker_response.unwrap())
    }
}