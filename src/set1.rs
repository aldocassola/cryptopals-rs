use aes::{
    Aes128Dec,
    cipher::{BlockDecrypt, Key, KeyInit, generic_array::GenericArray},
};
use base64::prelude::*;
use hex;
use std::{
    collections::{BinaryHeap, HashMap},
    fs::File,
    io::{BufRead, Read},
};

pub fn hex_to_base64(input: &str) -> String {
    BASE64_STANDARD.encode(hex::decode(input).unwrap_or(vec![]))
}

pub fn xor(left_bytes: &[u8], right_bytes: &[u8]) -> Vec<u8> {
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

pub fn count_freqs(input: &[u8]) -> LangMap {
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

pub fn score(input: &[u8], freqs: &LangMap) -> f64 {
    input
        .iter()
        .map(|letter| freqs.get(letter).unwrap_or(&0f64))
        .fold(0f64, |acc, d| acc + d)
        / input.len() as f64
}

pub fn find_single_byte_key(input: &[u8], freqs: &LangMap) -> (Vec<u8>, u8, f64) {
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

pub fn repeated_key_xor<'a>(
    plain_text: &[u8],
    key: &[u8],
    result: &'a mut Vec<u8>,
) -> &'a mut Vec<u8> {
    result.resize(plain_text.len(), 0);

    for (idx, val) in plain_text.iter().enumerate() {
        result[idx] = val ^ key[idx % key.len()];
    }

    result
}

pub fn hamming_distance(left: &[u8], right: &[u8]) -> usize {
    assert_eq!(left.len(), right.len());
    assert!(left.len() < 2usize.pow(29));

    xor(left, right)
        .iter()
        .map(|diff| diff.count_ones() as usize)
        .fold(0, |acc, val| acc + val)
}

#[derive(Debug)]
pub struct LengthDist {
    norm_dist: f64,
    length: usize,
}

impl PartialOrd for LengthDist {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.norm_dist.partial_cmp(&other.norm_dist)
    }
}

impl Ord for LengthDist {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.norm_dist.partial_cmp(&other.norm_dist).unwrap()
    }
}

impl PartialEq for LengthDist {
    fn eq(&self, other: &Self) -> bool {
        self.norm_dist == other.norm_dist
    }
}

impl Eq for LengthDist {}

type LengthDistVec = Vec<LengthDist>;

pub fn make_key_length_distance(input: &[u8]) -> LengthDistVec {
    let max_key_len = 40;
    let data_to_key_ratio = input.len() as f64 / max_key_len as f64;
    let nblocks = if 20f64 < data_to_key_ratio {
        20
    } else {
        data_to_key_ratio as usize
    };
    let mut heap = BinaryHeap::<LengthDist>::new();

    for key_len in 2..max_key_len {
        if key_len * 2 > input.len() {
            return heap.into();
        }

        let block1 = &input[0..key_len * nblocks];
        let block2 = &input[key_len * nblocks..2 * key_len * nblocks];
        heap.push(LengthDist {
            norm_dist: hamming_distance(block1, block2) as f64 / (key_len * nblocks) as f64,
            length: key_len,
        });
    }

    heap.into_sorted_vec()
}

pub fn read_b64_lines(filename: &str) -> Vec<u8> {
    let mut b64encrypted = Vec::<u8>::new();
    File::open(filename)
        .unwrap()
        .read_to_end(&mut b64encrypted)
        .unwrap();
    BASE64_STANDARD
        .decode(&b64encrypted.lines().fold(Vec::<u8>::new(), |mut vec, ln| {
            vec.append(&mut ln.unwrap().into_bytes());
            vec
        }))
        .unwrap()
}

pub fn read_hex_lines(filename: &str) -> Vec<Vec<u8>> {
    let mut hexdata = Vec::<u8>::new();
    File::open(filename)
        .unwrap()
        .read_to_end(&mut hexdata)
        .unwrap();

    hexdata
        .lines()
        .map(|ln| hex::decode(ln.unwrap()).unwrap())
        .collect::<Vec<_>>()
}

const BLOCKSIZE: usize = 16;

pub fn aes_ecb_decrypt(ciphertext: &[u8]) -> Vec<u8> {
    let mut blocks = (0..ciphertext.len())
        .filter_map(|idx| match idx % BLOCKSIZE {
            0 => Some(*GenericArray::from_slice(&ciphertext[idx..idx + BLOCKSIZE])),
            _ => None,
        })
        .collect::<Vec<_>>();
    let key = Key::<Aes128Dec>::from_slice(b"YELLOW SUBMARINE");
    let cipher = Aes128Dec::new(key);
    cipher.decrypt_blocks(&mut blocks);
    blocks
        .iter()
        .map(|arr| Vec::<u8>::from(arr.as_slice()))
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        usize,
    };

    use super::*;

    fn make_english_map() -> LangMap {
        let corpus_file = File::open("testdata/huckleberry.txt").unwrap();
        let corpus_len = corpus_file.metadata().unwrap().len();
        make_lang_map(&mut BufReader::new(corpus_file), corpus_len)
    }

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
        let english_map = make_english_map();
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
            String::from_utf8(max_line_score.2.clone()).unwrap_or("<invalid utf8>".into())
        );
        assert!(max_line_score.0 == 170);
        assert!("Now that the party is jumping\n".as_bytes() == max_line_score.2)
    }

    #[test]
    fn challenge5() {
        let plaintext = b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let key = b"ICE";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let ciphertext = repeated_key_xor(plaintext, key, &mut ciphertext);

        assert_eq!(
            *ciphertext,
            hex::decode(
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            )
            .unwrap()
        )
    }

    #[test]
    fn challenge6() {
        let s1 = "this is a test";
        let s2 = "wokka wokka!!!";
        assert_eq!(hamming_distance(s1.as_bytes(), s2.as_bytes()), 37);
        let ciphertext = read_b64_lines("testdata/6.txt");
        let weights = make_key_length_distance(&ciphertext);
        println!("Weights: {:?}", weights);

        let english_map = make_english_map();
        let mut trial_plaintexts: Vec<String> = vec![];
        for w in weights[0..1].iter() {
            let key_len = w.length;
            let mut chunks: Vec<Vec<u8>> = vec![vec![]; key_len];
            for (idx, byt) in ciphertext.iter().enumerate() {
                chunks[idx % key_len].push(*byt);
            }

            let mut key: Vec<u8> = Vec::new();
            for (key_idx, _chunk) in chunks.iter().enumerate() {
                let (_out, kb, _) = find_single_byte_key(&chunks[key_idx], &english_map);
                key.push(kb);
            }

            let mut buf: Vec<u8> = vec![];
            let trial_decrypt = repeated_key_xor(&ciphertext, &key, &mut buf);
            match String::from_utf8(trial_decrypt.to_vec()).ok() {
                Some(plaintext) => {
                    println!("{:?} yielded {}", w, plaintext);
                    trial_plaintexts.push(plaintext);
                }
                None => println!("{:?} failed", w),
            }
        }
    }

    #[test]
    fn challenge7() {
        let ciphertext = read_b64_lines("testdata/7.txt");
        let blocks = aes_ecb_decrypt(&ciphertext);
        println!("{}", String::from_utf8(blocks).unwrap());
    }

    #[test]
    fn challenge8() {
        let mut block_map: HashMap<&[u8], usize> = HashMap::new();
        let lines = read_hex_lines("testdata/8.txt");

        for (lnum, line) in lines.iter().enumerate() {
            for idx in (0..line.len()).step_by(BLOCKSIZE) {
                let v = &line[idx..idx + BLOCKSIZE];
                match block_map.get(v) {
                    Some(lnum) => {
                        println!(
                            "AES ECB found on line ({}:{}):{:?}\n repeating block:{:?}",
                            lnum,
                            idx,
                            hex::encode(&lines[*lnum]),
                            hex::encode(v),
                        )
                    }
                    None => {
                        block_map.insert(v, lnum);
                    }
                }
            }
        }
    }
}
