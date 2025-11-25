use base64::prelude::*;
use hex;
use std::{collections::HashMap, io::Read};

pub fn hex_to_base64(input: &str) -> String {
    BASE64_STANDARD.encode(hex::decode(input).unwrap_or(vec![]))
}

pub fn xor(left_bytes: &Vec<u8>, right_bytes: &Vec<u8>) -> Vec<u8> {
    if left_bytes.len() != right_bytes.len() {
        panic!("uneven strings")
    }

    left_bytes
        .iter()
        .zip(right_bytes.iter())
        .map(|(l, r)| l ^ r)
        .collect::<Vec<_>>()
}

type LangMap = HashMap<u8, f64>;

pub fn make_lang_map<B: Read>(rd: &mut B, sz: u64) -> LangMap {
    rd.bytes()
        .filter_map(|b| b.ok())
        .map(|b| b.to_ascii_lowercase())
        .fold(LangMap::new(), |mut acc, k| {
            *acc.entry(k).or_insert(1f64) += 1f64;
            acc
        })
        .iter()
        .map(|(k, v)| (*k, v / sz as f64))
        .collect::<LangMap>()
}

pub fn count_freqs(input: &Vec<u8>) -> LangMap {
    let mut hash_counts: HashMap<u8, i64> = HashMap::new();
    for letter in input {
        hash_counts
            .entry(*letter)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    hash_counts
        .iter()
        .map(|(letter, count)| (*letter, *count as f64 / input.len() as f64))
        .collect::<LangMap>()
}

pub fn score(input: &Vec<u8>, freqs: &LangMap) -> f64 {
    input
        .iter()
        .map(|letter| freqs.get(letter).unwrap_or(&0f64))
        .fold(0f64, |acc, d| acc + d)
        / input.len() as f64
}

pub fn find_single_byte_key(input: &Vec<u8>, freqs: &LangMap) -> (Vec<u8>, u8, f64) {
    let mut max: (f64, i32) = (0f64, -1);

    for key in 0..255 {
        let xor_pad = vec![key as u8; input.len()];
        let trial = xor(&input, &xor_pad);

        let score = score(&trial, &freqs);
        if score > max.0 {
            max = (score, key.into());
        }
    }

    (
        input.iter().map(|ch| ch ^ max.1 as u8).collect::<Vec<_>>(),
        max.1 as u8,
        max.0,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    use super::*;

    #[test]
    fn challenge1() {
        assert!(
            hex_to_base64(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            ) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
        assert!(hex_to_base64("") == "")
    }

    #[test]
    fn challenge2() {
        let left = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let right = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();
        assert!(xor(&left, &right) == expected)
    }

    #[test]
    fn challenge3() {
        let corpus_file = File::open("testdata/huckleberry.txt").unwrap();
        let corpus_len = corpus_file.metadata().unwrap().len();
        let english_map = make_lang_map(&mut BufReader::new(corpus_file), corpus_len);
        let input =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let (output, key, _) = find_single_byte_key(&input, &english_map);
        let msg = String::from_utf8(output).unwrap();
        println!("Found message \"{msg}\" with key {key}");
    }

    #[test]
    fn challenge4() {
        let encrypted_strings = File::open("testdata/4.txt").unwrap();
        let corpus_file = File::open("testdata/huckleberry.txt").unwrap();
        let corpus_len = corpus_file.metadata().unwrap().len();
        let english_map = make_lang_map(&mut BufReader::new(corpus_file), corpus_len);
        let mut max_line_score: (i32, f64, Vec<u8>) = (-1, 0f64, vec![]);

        for (lnum, line) in BufReader::new(encrypted_strings).lines().enumerate() {
            let (maybe_plaintext, _, score) =
                find_single_byte_key(&hex::decode(&line.unwrap()).unwrap(), &english_map);

            if score > max_line_score.1 {
                max_line_score = (lnum as i32, score, maybe_plaintext);
            }
        }

        println!(
            "{}: ({}) => {:?}",
            max_line_score.0,
            max_line_score.1,
            String::from_utf8(max_line_score.2.to_vec()).unwrap_or(String::from("<invalid utf8>"))
        )
    }
}
