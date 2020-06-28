use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use regex::Regex;

fn find_payload(s: &str) -> &str {
    let re = Regex::new("(?:.*<~)((?s).*)(?:~>.*)").expect("Failed to compile regex");
    let cap = match re.captures(&s) {
        Some(captures) => captures.get(1).expect("Failed to match regex"),
        None => panic!("Failed to match regex"),
    };
    
    unsafe { s.get_unchecked(cap.start()..cap.end())}
}

fn read_input_file(path: &str) -> String {
    let path = Path::new(path);
    let mut file = File::open(path).expect("Could not read file");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("Failed to read file into string");
    s
}

fn write_output_file(path: &str, data: &[u8]) {
    let path_out = Path::new(path);
    let mut file_out = File::create(path_out).expect("Could not open file for writing");
    file_out.write(data).expect("Failed writing to file");
}

fn clean_payload(payload: &str) -> String {
    payload.replace(|c: char| c == '\n' || c == '\r', "")
}

fn decode_ascii85(input: &str) -> String {
    let bytes = input.as_bytes();

    let num_bytes_to_skip = match 5 - bytes.len() % 5 {
        5 => 0,
        x => x,
    };

    let mut decoded = bytes.chunks(5)
        .map(|chunk| {
            let mut dec = 0u32;
            chunk.iter().enumerate().for_each(|(i, c)| {
                dec += (c-33) as u32 * 85u32.pow(4 - i as u32);
            });
            for i in 0..5 - chunk.len() {
                dec += 84u32 * 85u32.pow(i as u32);
            }
            let dec_s = String::from(unsafe { std::str::from_utf8_unchecked(&dec.to_be_bytes()) });
            dec_s
        })
        .collect::<String>();

    decoded.replace_range(decoded.len() - num_bytes_to_skip..decoded.len(), "");
    decoded
}

fn decode_flip_and_shift(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| (b ^ 0b01010101u8).rotate_right(1))
        .collect()
}

fn decode_parity_bit(input: &[u8]) -> Vec<u8> {
    let mut accumulator = 0u8;
    let mut num_bits_in_accumulator = 0u8;
    input.iter()
        .filter_map(|b| {
            let parity = b & 0b1u8;
            let data = b & 0b11111110u8;
            if parity == (data.count_ones() as u8 & 0b1u8) {
                if num_bits_in_accumulator > 0 {
                    let num_bits_used_for_next_byte = (8u8 - num_bits_in_accumulator) % 8u8;
                    let next_byte = accumulator | (data >> num_bits_in_accumulator);
                    num_bits_in_accumulator = 7u8 - num_bits_used_for_next_byte;
                    accumulator = data << num_bits_used_for_next_byte;
                    Some(next_byte)
                } else {
                    num_bits_in_accumulator = 7u8;
                    accumulator = data;
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

fn decode_onion_0() {
    let raw_input = read_input_file("data/onion0.txt");
    let payload = find_payload(&raw_input);
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    write_output_file("data/onion1.txt", decoded.as_bytes());
}

fn decode_onion_1() {
    let raw_input = read_input_file("data/onion1.txt");
    let payload = find_payload(&raw_input);
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_flip_and_shift(decoded.as_bytes());
    write_output_file("data/onion2.txt", decoded.as_slice());
}

fn decode_onion_2() {
    let raw_input = read_input_file("data/onion2.txt");
    let payload = find_payload(&raw_input);
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_parity_bit(decoded.as_bytes());
    write_output_file("data/onion3.txt", decoded.as_slice());
}

fn main() {
    decode_onion_0();
    decode_onion_1();
    decode_onion_2();
}
