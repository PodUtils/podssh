use super::*;

/// What a server reads, written from the spec (v2fly's page of the AEAD
/// header, and Xray-core's `aead/decrypt.go`): the auth ID opened and its
/// checksum held, then the length and the header under the keys of the
/// auth ID and the nonce, then the header's own FNV-1a.
fn server_opens(cmd_key: &[u8; 16], data: &[u8]) -> Result<(u64, Vec<u8>), &'static str> {
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    let auth: [u8; 16] = data[..16].try_into().unwrap();
    let aes = aes::Aes128::new(&kdf16(cmd_key, &[kdf::AUTH_ID_KEY]).into());
    let mut block = auth.into();
    aes.decrypt_block(&mut block);
    let plain: [u8; 16] = block.into();
    if kdf::crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return Err("the auth ID's checksum");
    }
    let unix = u64::from_be_bytes(plain[..8].try_into().unwrap());
    let nonce = &data[34..42];
    let path = |label: &'static [u8]| -> [&[u8]; 3] { [label, &auth[..], nonce] };
    let len_aead = Aead::new(AeadId::Aes128Gcm, &kdf16(cmd_key, &path(kdf::HEADER_LEN_KEY))).unwrap();
    let mut len = data[16..34].to_vec();
    len_aead.open_in_place(&kdf12(cmd_key, &path(kdf::HEADER_LEN_IV)), &auth, &mut len).ok_or("the length")?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let aead = Aead::new(AeadId::Aes128Gcm, &kdf16(cmd_key, &path(kdf::HEADER_KEY))).unwrap();
    let mut header = data[42..42 + len + 16].to_vec();
    let n = aead.open_in_place(&kdf12(cmd_key, &path(kdf::HEADER_IV)), &auth, &mut header).ok_or("the header")?;
    header.truncate(n);
    let (body, check) = header.split_at(n - 4);
    if kdf::fnv1a(body) != u32::from_be_bytes(check.try_into().unwrap()) {
        return Err("the header's checksum");
    }
    Ok((unix, body.to_vec()))
}

fn keys() -> Keys {
    let mut random = [0u8; 33];
    random.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
    Keys::new(&random)
}

/// The header that a server opens names the keys, the option S, the
/// cipher and padding, TCP, and the target port first; a name is its
/// length and its bytes.
#[test]
fn a_sealed_header_opens_as_the_spec_reads_it() {
    let cmd = kdf::cmd_key(&[0x55; 16]);
    let k = keys();
    let plain = request(&k, Cipher::Aes128Gcm, "example.com", 22, &[9, 9, 9]).unwrap();
    let sealed = seal(&cmd, &plain, 1_700_000_123, [4, 3, 2, 1], [8; 8]).unwrap();
    let (unix, body) = server_opens(&cmd, &sealed).unwrap();
    assert_eq!(unix, 1_700_000_123);
    assert_eq!(body[0], 1);
    assert_eq!(&body[1..17], &k.request_iv);
    assert_eq!(&body[17..33], &k.request_key);
    assert_eq!(body[33], k.check);
    assert_eq!(body[34], 0x01, "the option S alone");
    assert_eq!(body[35], (3 << 4) | 3, "3 bytes of padding, AES-128-GCM");
    assert_eq!(&body[36..38], &[0, 1], "reserved, then TCP");
    assert_eq!(&body[38..40], &22u16.to_be_bytes());
    assert_eq!(body[40], 2);
    assert_eq!(usize::from(body[41]), "example.com".len());
    assert_eq!(&body[42..53], b"example.com");
    assert_eq!(&body[53..], &[9, 9, 9]);
    // Planted: another user's key opens nothing.
    assert!(server_opens(&kdf::cmd_key(&[0x56; 16]), &sealed).is_err());
}

#[test]
fn addresses_take_their_types_and_a_bad_target_is_refused() {
    let k = keys();
    let v4 = request(&k, Cipher::ChaCha20Poly1305, "192.0.2.7", 443, &[]).unwrap();
    assert_eq!(v4[35], 4);
    assert_eq!(&v4[40..45], &[1, 192, 0, 2, 7]);
    let v6 = request(&k, Cipher::Aes128Gcm, "[2001:db8::1]", 443, &[]).unwrap();
    assert_eq!(v6[40], 3);
    assert_eq!(v6[41], 0x20);
    assert!(request(&k, Cipher::Aes128Gcm, &"a".repeat(256), 1, &[]).is_err());
    assert!(request(&k, Cipher::Aes128Gcm, "a", 1, &[0; 16]).is_err());
}

/// The answer that a server seals (`aead` in Xray-core's
/// `EncodeResponseHeader`) opens; another byte is told.
#[test]
fn the_answer_opens_and_its_byte_is_checked() {
    let k = keys();
    let seal_answer = |first: u8| {
        let mut len = 4u16.to_be_bytes().to_vec();
        let a = Aead::new(AeadId::Aes128Gcm, &kdf16(&k.answer_key, &[kdf::RESP_LEN_KEY])).unwrap();
        a.seal_in_place(&kdf12(&k.answer_iv, &[kdf::RESP_LEN_IV]), &[], &mut len).unwrap();
        let mut head = vec![first, 0, 0, 0];
        let a = Aead::new(AeadId::Aes128Gcm, &kdf16(&k.answer_key, &[kdf::RESP_KEY])).unwrap();
        a.seal_in_place(&kdf12(&k.answer_iv, &[kdf::RESP_IV]), &[], &mut head).unwrap();
        (len, head)
    };
    let (len, mut head) = seal_answer(k.check);
    assert_eq!(answer_len(&k, &len.clone().try_into().unwrap()), Some(4));
    assert_eq!(answer(&k, &mut head), Some(true));
    let (_, mut other) = seal_answer(k.check.wrapping_add(1));
    assert_eq!(answer(&k, &mut other), Some(false));
    let mut broken = len;
    broken[0] ^= 1;
    assert_eq!(answer_len(&k, &broken.try_into().unwrap()), None);
}
