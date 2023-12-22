#![allow(unused)]

use serde_json;
use serde_bencode::de;
use serde_bytes::ByteBuf;
use serde::{Deserialize};
use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{self, Read};
// Available if you need it!
// use serde_bencode

#[allow(dead_code)]

#[derive(Debug, Deserialize)]
struct TorrentInfo {
    pub length: i64,
    pub name: String,
    // Need this or the parse fails because the key value in the torrent file is "piece length", but serde can't find a matching key value in the struct
    #[serde(rename="piece length")]
    pub piece_length: i64,
    pub pieces: ByteBuf, 
}

#[derive(Debug, Deserialize)]
struct Torrent {
    info: TorrentInfo,
    #[serde(default)]
    announce: Option<String>,
    #[serde(rename="created by")]
    created_by: Option<String>,
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
fn main() {
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
        match torrent_data {
            Ok(buf) => {
                match de::from_bytes::<Torrent>(&buf) {
                    Ok(t) => println!("{:?}", t),
                    Err(e) => panic!("{}", e)
                }
            }
            Err(e) => panic!("{}", e)
        }
    } else {
       println!("unknown command: {}", args[1])
    }
}
