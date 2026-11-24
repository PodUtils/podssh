//! A TPM in software, for the tests: it reads the commands that podssh
//! sends as a TPM reads them (part 3), keeps PCRs, a storage key, keys and
//! policy sessions, and answers in the bytes of a TPM. Its keys sign
//! through aws-lc-rs; as that hashes the message itself, a test names the
//! messages that it will ask to have signed ([`SoftTpm::messages`]).
//!
//! What it enforces is what a sealed key rests on: a key loads only in the
//! TPM that made it (its private blob carries this TPM's seed), a key with
//! no `userWithAuth` refuses the password session, a policy session signs
//! only when its digest is the key's `authPolicy`, and `TPM2_PolicyPCR`
//! with a digest that the PCRs do not hold is refused.

use std::collections::HashMap;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use super::cmd::*;
use super::flow::Transport;
use super::policy::{sha256, Pcrs, CC_POLICY_PCR};
use super::public::{storage_template, EccPublic, USER_WITH_AUTH};
use super::wire::{In, Out, RH_OWNER, RS_PW, ST_NO_SESSIONS, ST_SESSIONS};

/// Response codes, as a TPM gives them with their place.
pub(super) const RC_VALUE_P1: u32 = 0x1C4;
pub(super) const RC_POLICY_FAIL_S1: u32 = 0x99D;
pub(super) const RC_INTEGRITY_P1: u32 = 0x1DF;
pub(super) const RC_AUTH_UNAVAILABLE: u32 = 0x12F;
const RC_HANDLE_H1: u32 = 0x18B;
const RC_COMMAND_CODE: u32 = 0x143;

enum Object {
    Storage,
    Key(usize),
    Session { trial: bool, digest: Vec<u8> },
}

struct Key {
    pair: EcdsaKeyPair,
    area: EccPublic,
}

pub(super) struct SoftTpm {
    seed: [u8; 16],
    pub pcrs: [[u8; 32]; 24],
    objects: HashMap<u32, Object>,
    next: u32,
    keys: Vec<Key>,
    /// The messages whose SHA-256 a signature may be asked for.
    pub messages: Vec<Vec<u8>>,
    /// Each command, as it came.
    pub sent: Vec<Vec<u8>>,
}

impl SoftTpm {
    pub fn new() -> Self {
        SoftTpm {
            seed: rand::random(),
            pcrs: [[0u8; 32]; 24],
            objects: HashMap::new(),
            next: 0,
            keys: Vec::new(),
            messages: Vec::new(),
            sent: Vec::new(),
        }
    }

    /// Extend a PCR of the SHA-256 bank, as a boot measures.
    pub fn extend(&mut self, index: usize, measured: &[u8]) {
        let event = sha256(measured);
        self.pcrs[index] = sha256(&[self.pcrs[index], event].concat());
    }

    /// The handles that are loaded: none after each operation that ended.
    pub fn loaded(&self) -> usize {
        self.objects.len()
    }

    fn handle(&mut self, base: u32, object: Object) -> u32 {
        self.next += 1;
        let handle = base | self.next;
        self.objects.insert(handle, object);
        handle
    }

    fn answer(&mut self, command: &[u8]) -> Result<(Vec<u32>, Vec<u8>, bool), u32> {
        let mut input = In::new(command);
        let tag = input.u16().map_err(|_| RC_COMMAND_CODE)?;
        let _size = input.u32().map_err(|_| RC_COMMAND_CODE)?;
        let code = input.u32().map_err(|_| RC_COMMAND_CODE)?;
        let handles = match code {
            CC_CREATE_PRIMARY | CC_CREATE | CC_LOAD | CC_SIGN | CC_POLICY_PCR | CC_POLICY_GET_DIGEST => 1,
            CC_PCR_EXTEND => 1,
            CC_START_AUTH_SESSION => 2,
            _ => 0,
        };
        let mut found = Vec::new();
        for _ in 0..handles {
            found.push(input.u32().map_err(|_| RC_COMMAND_CODE)?);
        }
        let mut auth = None;
        if tag == ST_SESSIONS {
            let size = input.u32().map_err(|_| RC_COMMAND_CODE)? as usize;
            let mut area = In::new(input.take(size).map_err(|_| RC_COMMAND_CODE)?);
            auth = Some(area.u32().map_err(|_| RC_COMMAND_CODE)?);
        }
        let p = &mut input;
        let bad = |_: String| RC_COMMAND_CODE;
        match code {
            CC_GET_CAPABILITY => {
                let mut out = Out::default();
                out.u8(0).u32(6).u32(1).u32(0x105).raw(b"SOFT");
                Ok((vec![], out.finish().map_err(bad)?, false))
            }
            CC_PCR_READ => {
                let asked = Pcrs::read_selection(p).map_err(bad)?;
                // A TPM reads 8 at most at once.
                let read: Vec<u8> = asked.numbers().into_iter().take(8).collect();
                let text: Vec<String> = read.iter().map(u8::to_string).collect();
                let read_set = Pcrs::parse(&text.join(",")).map_err(bad)?;
                let mut out = Out::default();
                out.u32(7).raw(&read_set.selection()).u32(read.len() as u32);
                for n in read {
                    out.sized(&self.pcrs[usize::from(n)]);
                }
                Ok((vec![], out.finish().map_err(bad)?, false))
            }
            CC_PCR_EXTEND => {
                p.u32().map_err(bad)?;
                p.u16().map_err(bad)?;
                let digest = p.take(32).map_err(bad)?;
                let index = found[0] as usize;
                self.pcrs[index] = sha256(&[&self.pcrs[index][..], digest].concat());
                Ok((vec![], vec![], true))
            }
            CC_CREATE_PRIMARY => {
                p.take(6).map_err(bad)?;
                let template = p.sized_whole().map_err(bad)?;
                if found[0] != RH_OWNER || template != storage_template().map_err(bad)?.as_slice() {
                    return Err(RC_HANDLE_H1);
                }
                let handle = self.handle(0x8000_0000, Object::Storage);
                Ok((vec![handle], vec![], true))
            }
            CC_CREATE => {
                if !matches!(self.objects.get(&found[0]), Some(Object::Storage)) {
                    return Err(RC_HANDLE_H1);
                }
                p.take(6).map_err(bad)?;
                let template = p.sized_whole().map_err(bad)?.to_vec();
                let mut area = EccPublic::parse(&template).map_err(bad)?;
                let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| RC_COMMAND_CODE)?;
                let point = pair.public_key().as_ref().to_vec();
                area.x = point[1..33].to_vec();
                area.y = point[33..].to_vec();
                // The template ends with two empty coordinates.
                let mut public = template[2..template.len() - 4].to_vec();
                for c in [&area.x, &area.y] {
                    public.extend_from_slice(&(c.len() as u16).to_be_bytes());
                    public.extend_from_slice(c);
                }
                let mut private = self.seed.to_vec();
                private.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
                self.keys.push(Key { pair, area });
                let mut out = Out::default();
                out.sized(&private).sized(&public).sized(&[]).sized(&[]).u16(0x8021).u32(RH_OWNER).sized(&[]);
                Ok((vec![], out.finish().map_err(bad)?, true))
            }
            CC_LOAD => {
                if !matches!(self.objects.get(&found[0]), Some(Object::Storage)) {
                    return Err(RC_HANDLE_H1);
                }
                let private = p.sized().map_err(bad)?;
                if private.len() != 20 || private[..16] != self.seed {
                    return Err(RC_INTEGRITY_P1);
                }
                let index = u32::from_be_bytes([private[16], private[17], private[18], private[19]]) as usize;
                let handle = self.handle(0x8000_0000, Object::Key(index));
                Ok((vec![handle], vec![0, 0], true))
            }
            CC_START_AUTH_SESSION => {
                let nonce = p.sized().map_err(bad)?;
                if !(16..=32).contains(&nonce.len()) {
                    return Err(0x1D5);
                }
                p.sized().map_err(bad)?;
                let kind = p.u8().map_err(bad)?;
                let session = Object::Session { trial: kind == SE_TRIAL, digest: vec![0; 32] };
                let handle = self.handle(0x0300_0000, session);
                let mut out = Out::default();
                out.sized(&[7u8; 32]);
                Ok((vec![handle], out.finish().map_err(bad)?, false))
            }
            CC_POLICY_PCR => {
                let given = p.sized().map_err(bad)?.to_vec();
                let start = command.len() - p.rest().len();
                let pcrs = Pcrs::read_selection(p).map_err(bad)?;
                let selection = command[start..].to_vec();
                let values: Vec<[u8; 32]> = pcrs.numbers().iter().map(|n| self.pcrs[usize::from(*n)]).collect();
                let now = super::policy::pcr_digest(&values).to_vec();
                let Some(Object::Session { trial, digest }) = self.objects.get_mut(&found[0]) else {
                    return Err(RC_HANDLE_H1);
                };
                if !*trial && !given.is_empty() && given != now {
                    return Err(RC_VALUE_P1);
                }
                let used = if *trial && !given.is_empty() { given } else { now };
                let message = [digest.as_slice(), &CC_POLICY_PCR.to_be_bytes(), &selection, &used].concat();
                *digest = sha256(&message).to_vec();
                Ok((vec![], vec![], false))
            }
            CC_POLICY_GET_DIGEST => {
                let Some(Object::Session { digest, .. }) = self.objects.get(&found[0]) else {
                    return Err(RC_HANDLE_H1);
                };
                let mut out = Out::default();
                out.sized(digest);
                Ok((vec![], out.finish().map_err(bad)?, false))
            }
            CC_FLUSH_CONTEXT => {
                let handle = p.u32().map_err(bad)?;
                self.objects.remove(&handle).map(|_| (vec![], vec![], false)).ok_or(0x1CB)
            }
            CC_SIGN => self.sign(found[0], auth.unwrap_or(0), p),
            _ => Err(RC_COMMAND_CODE),
        }
    }

    fn sign(&mut self, key: u32, auth: u32, p: &mut In) -> Result<(Vec<u32>, Vec<u8>, bool), u32> {
        let Some(Object::Key(index)) = self.objects.get(&key) else { return Err(RC_HANDLE_H1) };
        let key = &self.keys[*index];
        if auth == RS_PW {
            if key.area.attributes & USER_WITH_AUTH == 0 {
                return Err(RC_AUTH_UNAVAILABLE);
            }
        } else {
            match self.objects.get(&auth) {
                Some(Object::Session { trial: false, digest }) if *digest == key.area.auth_policy => {}
                Some(Object::Session { .. }) => return Err(RC_POLICY_FAIL_S1),
                _ => return Err(0x98B),
            }
        }
        let digest = p.sized().map_err(|_| RC_COMMAND_CODE)?;
        let message = self.messages.iter().find(|m| sha256(m).as_slice() == digest).ok_or(RC_COMMAND_CODE)?;
        let signature = key.pair.sign(&SystemRandom::new(), message).map_err(|_| RC_COMMAND_CODE)?;
        let (r, s) = signature.as_ref().split_at(32);
        let mut out = Out::default();
        out.u16(0x0018).u16(0x000B).sized(r).sized(s);
        // The session ends with the command, as continueSession is clear.
        self.objects.remove(&auth);
        Ok((vec![], out.finish().map_err(|_| RC_COMMAND_CODE)?, true))
    }
}

impl Transport for SoftTpm {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        self.sent.push(command.to_vec());
        let mut out = Out::default();
        match self.answer(command) {
            Ok((handles, params, sessions)) => {
                let tag = if sessions { ST_SESSIONS } else { ST_NO_SESSIONS };
                let mut body = Out::default();
                for h in &handles {
                    body.u32(*h);
                }
                if sessions {
                    // The parameters' size, then one answer of a session.
                    body.u32(params.len() as u32).raw(&params).sized(&[]).u8(0).sized(&[]);
                } else {
                    body.raw(&params);
                }
                let body = body.finish()?;
                out.u16(tag).u32(10 + body.len() as u32).u32(0).raw(&body);
            }
            Err(code) => {
                out.u16(ST_NO_SESSIONS).u32(10).u32(code);
            }
        }
        out.finish()
    }
}
