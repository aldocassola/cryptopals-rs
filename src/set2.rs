use aes::cipher::{
    BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, generic_array::GenericArray,
};
use rand::{Rng, RngCore, distr::Uniform};

use crate::set1::xor_mut;

pub fn pad_pkcs7<C: BlockSizeUser + Sized>(input: &mut Vec<u8>) -> &mut Vec<u8> {
    let padding_length = C::block_size() - input.len() % C::block_size();
    let mut pad = vec![padding_length as u8; padding_length];
    input.append(&mut pad);
    input
}

pub fn unpad_pkcs7<C: BlockSizeUser + Sized>(
    input: &mut Vec<u8>,
) -> Result<&mut Vec<u8>, &'static str> {
    let mut check_good = input.len() % C::block_size() == 0;

    if input.len() < C::block_size() {
        check_good = false;
    }

    let last_block = &input[input.len() - C::block_size()..];
    let last_byte = last_block[C::block_size() - 1];
    check_good = check_good && last_byte <= C::block_size() as u8;
    let maybe_pad = &last_block[C::block_size() - last_byte as usize..];
    let all_bytes = maybe_pad.iter().all(|e| *e == last_byte);

    if !check_good || !all_bytes {
        return Err("pkcs7 failed");
    }

    input.resize(input.len() - maybe_pad.len(), 0);
    Ok(input)
}

pub fn cbc_encrypt<'a, C: BlockSizeUser + BlockEncrypt + Sized>(
    cipher: &C,
    iv: &[u8],
    plaintext: &'a mut Vec<u8>,
) -> Result<&'a mut Vec<u8>, &'static str> {
    if plaintext.len() < C::block_size()
        || plaintext.len() % C::block_size() != 0
        || iv.len() != C::block_size()
    {
        return Err("cbc encrypt failed");
    }

    let mut last_ciphertext = iv.to_owned();

    for idx in (0..plaintext.len()).step_by(C::block_size()) {
        let cur_block = GenericArray::from_mut_slice(&mut plaintext[idx..idx + C::block_size()]);
        xor_mut(cur_block, &last_ciphertext);
        cipher.encrypt_block(cur_block);
        last_ciphertext.copy_from_slice(&cur_block);
    }

    Ok(plaintext)
}

pub fn cbc_decrypt<'a, C: BlockSizeUser + BlockDecrypt + Sized>(
    cipher: &C,
    iv: &[u8],
    ciphertext: &'a mut Vec<u8>,
) -> Result<&'a mut Vec<u8>, &'static str> {
    if ciphertext.len() < C::block_size()
        || ciphertext.len() % C::block_size() != 0
        || iv.len() != C::block_size()
    {
        return Err("cbc decrypt failed");
    }

    let mut last_ciphertext = iv.to_owned();
    for idx in (0..ciphertext.len()).step_by(C::block_size()) {
        let cur_block = GenericArray::from_mut_slice(&mut ciphertext[idx..idx + C::block_size()]);
        let cur_block_copy = cur_block.clone();
        cipher.decrypt_block(cur_block);
        xor_mut(cur_block, &last_ciphertext);
        last_ciphertext.copy_from_slice(&cur_block_copy);
    }

    Ok(ciphertext)
}

pub fn make_ecb_cbc_oracle<C: KeyInit + BlockEncrypt + BlockDecrypt + BlockSizeUser + Sized>()
-> impl FnMut(&[u8]) -> Vec<u8> {
    let mut key = vec![0u8; C::block_size()];
    let mut rng = rand::rng();
    let distr5_10 = Uniform::new(5usize, 11).unwrap();
    let coin_flip = Uniform::new(0, 2).unwrap();

    rng.fill_bytes(&mut key);

    let cipher = C::new(GenericArray::from_slice(&key));
    let oracle = move |input: &[u8]| -> Vec<u8> {
        let before_len: usize = rng.sample(distr5_10);
        let after_len: usize = rng.sample(distr5_10);
        let mut iv = vec![0u8; C::block_size()];
        let mut blocks = vec![0u8; before_len + after_len + input.len()];

        rng.fill_bytes(&mut blocks[0..before_len]);
        blocks[before_len..before_len + input.len()].copy_from_slice(input);
        rng.fill_bytes(&mut blocks[before_len + input.len()..]);
        rng.fill_bytes(&mut iv);
        let mut padded = pad_pkcs7::<C>(&mut blocks);

        let ecb_or_cbc = rng.sample(coin_flip);

        if ecb_or_cbc == 0 {
            return crate::set1::ecb_encrypt(&cipher, &padded);
        } else {
            return cbc_encrypt(&cipher, &iv, &mut padded).unwrap().to_vec();
        }
    };

    oracle
}

#[cfg(test)]
mod tests {
    use aes::{
        Aes128,
        cipher::{BlockSizeUser, KeyInit, typenum},
    };

    use crate::set1::is_ecb_ciphertext;

    use super::*;

    #[test]
    fn challenge9() {
        let mut sub = Vec::from("YELLOW SUBMARINE");
        let expected = Vec::from("YELLOW SUBMARINE\x04\x04\x04\x04");
        struct TwentyBlockSize {}
        impl BlockSizeUser for TwentyBlockSize {
            type BlockSize = typenum::U20;
        }
        assert_eq!(
            expected,
            *crate::set2::pad_pkcs7::<TwentyBlockSize>(&mut sub)
        );
    }

    #[test]
    fn challenge10() {
        let key = GenericArray::from_slice("YELLOW SUBMARINE".as_bytes());
        let cipher = Aes128::new(&key);
        let plain_cases: Vec<Vec<u8>> = vec![
            "123abc".into(),
            "12345678abcdefgh".into(),
            "12345678abcdefghi".into(),
            "yellow_submarineyellow_submarine".into(),
        ];
        let iv_cases = vec![
            vec![0; Aes128::block_size()],
            vec![42; Aes128::block_size()],
            vec![0xa5; Aes128::block_size()],
        ];

        for mut plaintext in plain_cases {
            for iv in &iv_cases {
                let plaintext_copy = plaintext.clone();
                let padded = crate::set2::pad_pkcs7::<Aes128>(&mut plaintext);
                let ciphertext = crate::set2::cbc_encrypt(&cipher, &iv, padded).unwrap();
                crate::set2::cbc_decrypt(&cipher, &iv, ciphertext).unwrap();
                let unpadded = crate::set2::unpad_pkcs7::<Aes128>(ciphertext).unwrap();
                assert_eq!(*unpadded, plaintext_copy);
            }
        }

        let mut file_ciphertext = crate::set1::read_b64_lines("testdata/10.txt");
        let iv = [0; 16];
        let file_plaintext = crate::set2::cbc_decrypt(&cipher, &iv, &mut file_ciphertext).unwrap();
        println!("{}", String::from_utf8(file_plaintext.to_vec()).unwrap());
    }

    #[test]
    fn challenge11() {
        let mut encrypt_oracle = make_ecb_cbc_oracle::<Aes128>();
        let plaintext = vec!['A' as u8; 64];
        let mut count_cbc = 0usize;
        let max_tests = 10_000;
        for _ in 0..max_tests {
            let ct = encrypt_oracle(&plaintext);
            match is_ecb_ciphertext(&ct) {
                Some(idx) => println!("found ECB at index {}", idx),
                None => {
                    println!("probably CBC");
                    count_cbc += 1;
                }
            }
        }

        println!("found CBC {} out of {} times", count_cbc, max_tests)
    }
}
