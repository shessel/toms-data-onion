use std::convert::TryInto;
use std::fmt::Debug;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use openssl::aes::{AesKey, unwrap_key};
use openssl::symm::{decrypt, Cipher};

use regex::Regex;

fn find_payload(string: &str) -> Option<&str> {
    let ascii85_payload_regex = Regex::new("(?:.*<~)((?s).*)(?:~>.*)").expect("Failed to compile regex");
    let captures = match ascii85_payload_regex.captures(&string) {
        Some(captures) => captures.get(1),
        None => panic!("Failed to match regex"),
    };
    
    captures.map(|capture| unsafe { string.get_unchecked(capture.start()..capture.end())})
}

fn read_input_file(path: &str) -> String {
    let path = Path::new(path);
    let mut file = File::open(path).expect("Could not read file");
    let mut content_string = String::new();
    file.read_to_string(&mut content_string).expect("Failed to read file into string");
    content_string
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
    input.iter().map(|byte| (byte ^ 0b01010101u8).rotate_right(1))
        .collect()
}

fn decode_parity_bit(input: &[u8]) -> Vec<u8> {
    let mut accumulator = 0u8;
    let mut num_bits_in_accumulator = 0u8;
    input.iter()
        .filter_map(|byte| {
            let parity = byte & 0b1u8;
            let data = byte & 0b11111110u8;
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

fn decode_32bit_xor_cyclic(input: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let mut key_index = 0 as usize;
    input
        .iter()
        .map(|byte| {
            let byte = byte ^ key_bytes[key_index];
            key_index = (key_index + 1) % key_bytes.len();
            byte
        })
        .collect()
}

#[test]
fn test_xor() {
    let original = [0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8];
    let key = [0xAAu8, 0xBBu8, 0xCCu8];
    let encrypted = vec![0xBBu8, 0x99u8, 0xFFu8, 0xEEu8, 0xEEu8, 0xAAu8, 0xDDu8];
    assert_eq!(decode_32bit_xor_cyclic(&original, &key), encrypted);
}

fn decode_unknown_32byte_xor(input: &[u8]) -> Vec<u8> {
    // We know that roughly the second half of the Title consists of '='
    // and that character 61 and 62 are line breaks.
    // That means if we xor the first 32 bytes with what we expect
    // for the next 32 and then use that to xor the next 32 bytes
    // the result should partially be the plain text result we
    // are looking for.
    let mut expected_second_32_bytes = ['=' as u8; 32];
    expected_second_32_bytes[28] = '\n' as u8;
    expected_second_32_bytes[29] = '\n' as u8;

    let mut intermediate_key = decode_32bit_xor_cyclic(&input[0..32], &expected_second_32_bytes);
    let intermediate_first_32_bytes = decode_32bit_xor_cyclic(&input[32..64], &intermediate_key);

    intermediate_key = decode_32bit_xor_cyclic(&input[0..32], &intermediate_first_32_bytes);

    // We also know that there is a line that reads
    // "==[ Payload ]===============================================".
    // Try to find the closest match in the intermediate decoded text.

    let intermediate_decoded = decode_32bit_xor_cyclic(input, &intermediate_key);

    let known_pattern = "==[ Payload ]===============================================".as_bytes();
    let mut best_match_count = 0;
    let mut best_match_start = 0;
    for byte_i in 0..intermediate_decoded.len() {
        let byte = intermediate_decoded[byte_i];
        if byte == known_pattern[0] {
            let mut match_len = 1;
            for match_i in 1..known_pattern.len() {
                let match_byte_i = byte_i + match_i;
                if match_byte_i < intermediate_decoded.len() {
                    let match_byte = intermediate_decoded[match_byte_i];
                    if match_byte == known_pattern[match_i] {
                        match_len += 1;
                    }
                } else {
                    continue;
                }
            }

            if match_len > best_match_count {
                best_match_start = byte_i;
                best_match_count = match_len;
            }
        }
    }

    // Use that match to patch up the intermediate key
    let best_match = &intermediate_decoded[best_match_start..best_match_start+known_pattern.len()];
    for i in 0..known_pattern.len() {
        let match_byte = best_match[i];
        let known_byte = known_pattern[i];
        if match_byte != known_byte {
            let full_text_i = best_match_start + i;
            intermediate_key[full_text_i % 32] = input[full_text_i] ^ known_byte;
        }
    }

    decode_32bit_xor_cyclic(input, &intermediate_key)
}

// only the parts that are necessary for layer 4
#[derive(Debug)]
struct IpHeader {
    source: u32,
    destination: u32,
    valid: bool,
}

impl IpHeader {
    pub fn from_bytes(bytes: &[u8]) -> IpHeader {
        let source = u32::from_be_bytes(bytes[12..16].try_into()
            .expect("not enough bytes to parse IP header"));
        let destination = u32::from_be_bytes(bytes[16..20].try_into()
            .expect("not enough bytes to parse IP header"));

        let mut checksum = bytes.chunks(2)
            .map(|chunk| {
                u16::from_be_bytes(chunk.try_into()
                    .expect("Couldn't convert to u16")) as u32
            })
            .fold(0u32, |lhs, rhs| lhs.wrapping_add(rhs));
        
        while checksum > 0xFFFF {
            let upper = (checksum & 0xFFFF0000) >> 16;
            let lower = checksum & 0xFFFF;
            checksum = lower + upper;
        }

        let valid = checksum == 0xFFFF;
        IpHeader {
            source,
            destination,
            valid
        }
    }
}

#[derive(Debug)]
struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    length: u16,
}

impl UdpHeader {
    pub fn from_bytes(bytes: &[u8]) -> UdpHeader {
        let source_port = u16::from_be_bytes(bytes[0..2].try_into()
            .expect("not enough bytes to parse UDP header"));
        let destination_port = u16::from_be_bytes(bytes[2..4].try_into()
            .expect("not enough bytes to parse UDP header"));
        let length = u16::from_be_bytes(bytes[4..6].try_into()
            .expect("not enough bytes to parse UDP header"));

        UdpHeader {
            source_port,
            destination_port,
            length,
        }
    }
}

fn decode_udp_ip(input: &[u8]) -> Vec<u8> {
    let mut byte_i = 0;
    let mut decoded = Vec::new();
    let expected_source = u32::from_be_bytes([10,1,1,10]);
    let expected_destination = u32::from_be_bytes([10,1,1,200]);
    while byte_i < input.len() {
        let ip_header_bytes = &input[byte_i..byte_i + 20];
        let ip_header = IpHeader::from_bytes(ip_header_bytes);
        byte_i += 20;

        let udp_header_bytes = &input[byte_i..byte_i + 8];
        let udp_header = UdpHeader::from_bytes(udp_header_bytes);

        let data = &input[byte_i..byte_i + udp_header.length as usize];

        let mut udp_checksum = (ip_header.source >> 16) as u32
            + (ip_header.source & 0xFFFF) as u32
            + (ip_header.destination >> 16) as u32
            + (ip_header.destination & 0xFFFF) as u32
            + 17
            + udp_header.length as u32;

        udp_checksum = data.chunks(2)
            .fold(udp_checksum, |sum, val| {
                let mut val_u16 = 0u16;
                for (i, &val) in val.iter().enumerate() {
                    val_u16 += (val as u16) << (8 * (1-i));
                }
                sum + val_u16 as u32
            });
        
        while udp_checksum > 0xFFFF {
            let upper = (udp_checksum & 0xFFFF0000) >> 16;
            let lower = udp_checksum & 0xFFFF;
            udp_checksum = lower + upper;
        }

        let udp_valid = udp_checksum == 0xFFFF;

        let good_package = ip_header.valid && udp_valid
            && ip_header.source == expected_source
            && ip_header.destination == expected_destination
            && udp_header.destination_port == 42069;
        
        if good_package {
            decoded.extend_from_slice(&data[8..]);
        }

        byte_i += udp_header.length as usize;
    }
    decoded
}

fn decode_known_aes(input: &[u8]) -> Vec<u8> {
    let kek_bytes = &input[..32];
    let mut key_iv = [0u8; 8];
    key_iv.clone_from_slice(&input[32..40]);
    let key_enc = &input[40..80];

    let kek = AesKey::new_decrypt(kek_bytes).unwrap();
    let mut key_bytes = [0u8; 32];
    unwrap_key(&kek, Some(key_iv), &mut key_bytes, &key_enc);

    let mut enc_iv = [0u8; 16];
    enc_iv.clone_from_slice(&input[80..96]);
    let enc = &input[96..];

    let cipher = Cipher::aes_256_cbc();
    decrypt(cipher, &key_bytes, Some(&enc_iv), enc).unwrap()
}

fn decode_onion_0() {
    let raw_input = read_input_file("data/onion0.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    write_output_file("data/onion1.txt", decoded.as_bytes());
}

fn decode_onion_1() {
    let raw_input = read_input_file("data/onion1.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_flip_and_shift(decoded.as_bytes());
    write_output_file("data/onion2.txt", decoded.as_slice());
}

fn decode_onion_2() {
    let raw_input = read_input_file("data/onion2.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_parity_bit(decoded.as_bytes());
    write_output_file("data/onion3.txt", decoded.as_slice());
}

fn decode_onion_3() {
    let raw_input = read_input_file("data/onion3.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_unknown_32byte_xor(decoded.as_bytes());
    write_output_file("data/onion4.txt", decoded.as_slice());
}

fn decode_onion_4() {
    let raw_input = read_input_file("data/onion4.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_udp_ip(decoded.as_bytes());
    write_output_file("data/onion5.txt", decoded.as_slice());
}

fn decode_onion_5() {
    let raw_input = read_input_file("data/onion5.txt");
    let payload = find_payload(&raw_input).expect("Failed to find payload");
    let payload = clean_payload(payload);
    let decoded = decode_ascii85(&payload);
    let decoded = decode_known_aes(decoded.as_bytes());
    write_output_file("data/onion6.txt", decoded.as_slice());
}

fn main() {
    decode_onion_0();
    decode_onion_1();
    decode_onion_2();
    decode_onion_3();
    decode_onion_4();
    decode_onion_5();
}
