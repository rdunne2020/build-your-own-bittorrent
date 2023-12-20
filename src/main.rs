use serde_json;
use std::env;
// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_value(encoded_value: &str) -> (usize, serde_json::Value) {
    // If encoded_value starts with a digit, it's a number
    let next_char = encoded_value.chars().next().unwrap();
    if next_char.is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number = number_string.parse::<i64>().unwrap();
        let string = &encoded_value[(colon_index + 1)..(colon_index + 1 + number as usize)];
        // Get this by seeing the size of the prefix number + 1 for the colon, then the length of the string
        let advance_length = colon_index + number as usize + 1;
        return (advance_length, serde_json::Value::String(string.to_string()));
    }
    else if next_char == 'i' {
        let integer_length = encoded_value.find('e').unwrap();
        let int_string = &encoded_value[1..integer_length];
        return (integer_length+1, serde_json::Value::Number(serde_json::Number::from(i64::from_str_radix(&int_string, 10).unwrap())));
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

fn decode_list(encoded_list: &str) -> (usize, Vec<serde_json::Value>) {
    let mut next_char = encoded_list.chars().peekable();
    let mut string_iter = encoded_list.chars();

    let mut token_list = vec![];
    let mut advance_length: usize = 0;

    // Move iterators forward to consume the leading 'l'
    next_char.next();
    string_iter.next();

    // Decode str
    while *next_char.peek().unwrap() != 'e' {
        if next_char.peek().unwrap().is_digit(10) || *next_char.peek().unwrap() == 'i' {
            let (token_length, val) = decode_value(string_iter.as_str());
            token_list.push(val);
            advance_length = token_length;
        }
        for _ in 0..advance_length {
            next_char.next();
            string_iter.next();
        }
    }
    return (advance_length, token_list);
}

fn decode_dict(encoded_list: &str) -> (usize, serde_json::Map<String, serde_json::Value>) {
    let mut next_char = encoded_list.chars().peekable();
    let mut string_iter = encoded_list.chars();

    let mut token_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut advance_length: usize = 0;

    // Advance the two iterators to consume the 'd'
    next_char.next();
    string_iter.next();

    // Decode str
    // TODO: Error handle, this will fail ugly mode
    while *next_char.peek().unwrap() != 'e' {
        // Read Key
        let (token_length, key) = decode_value(string_iter.as_str());
        advance_length = token_length;

        for _ in 0..advance_length {
            next_char.next();
            string_iter.next();
        }

        if next_char.peek().unwrap().is_digit(10) || *next_char.peek().unwrap() == 'i' {
            let (token_length, val) = decode_value(string_iter.as_str());
            advance_length = token_length;
            token_map.insert(String::from(key.as_str().unwrap()), val);
        }
        for _ in 0..advance_length {
            next_char.next();
            string_iter.next();
        }
    }
    return (advance_length, token_map);
}

fn decode_bencoded_input(encoded_value: &str) -> serde_json::Value {
   // If encoded_value starts with a digit, it's a number
//    let mut chars = encoded_value.chars();
   let mut peek_chars = encoded_value.chars().peekable();
   // Get first char
   let parsed_val: serde_json::Value = match peek_chars.peek().unwrap() {
       // Parse dict
       'd' => {
           let (_, val) = decode_dict(encoded_value);
           serde_json::Value::Object(val.into())
       },
       // Parse list
       'l' => {
           let (_, val) = decode_list(encoded_value);
           serde_json::Value::Array(val)
       },
       // Parse String prefixed with number or integer
       _ => {
           let (_, val) = decode_value(encoded_value);
           val
       }
   };

   return parsed_val;
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_decode() {
        // Remove leading L since the decode_bencoded_input function will strip it out
        let enc_str = "l5:helloi69ee";
        let (_, tokens) = decode_list(enc_str);

        println!("{:?}", tokens);

        assert_eq!(tokens, vec![serde_json::json!("hello"), serde_json::json!(69)]);
    }
    #[test]
    fn test_map_decode() {
        let enc_str = "d3:foo3:bar5:helloi52ee";
        let (_, tokens) = decode_dict(enc_str);

        assert_eq!(serde_json::Value::Object(tokens.into()), serde_json::json!({"foo": "bar", "hello": 52}));
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
       // Uncomment this block to pass the first stage
       let encoded_value = &args[2];
       let decoded_value = decode_bencoded_input(encoded_value);
       println!("{}", decoded_value.to_string());
    } else {
       println!("unknown command: {}", args[1])
    }
}
