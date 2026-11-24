//! podssh's own SFTP requests (T-150, `podssh_ssh::sftp::sums`): a request
//! or a reply that parses goes back to the same bytes; a reply that parses
//! fits its request (no more bytes hashed than asked, one digest for each
//! block); nothing panics on bytes of a peer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ssh::sftp::sums::{blocks_of, encode_reply, encode_request, parse_reply, parse_request, Asked};

fuzz_target!(|data: &[u8]| {
    for blocks in [false, true] {
        if let Ok(asked) = parse_request(data, blocks) {
            assert_eq!(encode_request(&asked), data);
        }
    }
    // The first 12 bytes choose the request that a reply answers.
    let Some((head, reply)) = data.split_at_checked(12) else { return };
    let len = u64::from_be_bytes(head[..8].try_into().unwrap_or([0; 8]));
    let block = u32::from_be_bytes(head[8..].try_into().unwrap_or([0; 4]));
    let asked = Asked { handle: "1".into(), offset: 0, len, block };
    if let Ok(sums) = parse_reply(reply, &asked) {
        assert!(asked.len == 0 || sums.hashed <= asked.len);
        assert_eq!(sums.block, asked.block);
        assert_eq!(sums.sums.len() as u64, blocks_of(sums.hashed, sums.block));
        assert_eq!(encode_reply(&sums), reply);
    }
});
