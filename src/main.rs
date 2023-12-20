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

fn decode_bencoded_input(encoded_value: &str) -> serde_json::Value {
   // If encoded_value starts with a digit, it's a number
   let mut chars = encoded_value.chars();
   let mut peek_chars = chars.clone().peekable();
   // Get first char
   let parsed_val: serde_json::Value = match peek_chars.peek().unwrap() {
       // Parse list
       'l' => {
           // Advance chars
           chars.next();
           let (_, val) = decode_list(chars.as_str());
           serde_json::Value::Array(val)
       },
       // Parse String prefixed with number or integer
       _ => {
           let (_, val) = decode_value(chars.as_str());
           val
       }
   };

   return parsed_val;
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_list_decode() {
        // Remove leading L since the decode_bencoded_input function will strip it out
        let enc_str = "5:helloi69ee";
        let (_, tokens) = decode_list(enc_str);

        println!("{:?}", tokens);

        assert_eq!(tokens, vec![json!("hello"), json!(69)]);
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
