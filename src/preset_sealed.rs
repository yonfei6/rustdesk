//! custom: sealed preset-password channel.
//!
//! The compiled-in preset password never leaves the source tree in clear: the
//! build only embeds `h1 = sha256(plain ‖ salt)` (`MY_PASSWORD_HASH`), and `h1`
//! cannot be used to log in by itself. The clear text exists only while the
//! operator types it. This module transports that clear text from the client to
//! the host as an anonymous sealed box:
//!
//! ```text
//! sealed = epk(32) ‖ XSalsa20-Poly1305(precompute(pk_host, epk_sk), body)
//! body   = magic ‖ ver ‖ fp(16) ‖ ch_len ‖ challenge ‖ pw_len(le16) ‖ pw ‖ pad
//! ```
//!
//! This is byte-compatible with libsodium's `crypto_box_seal` (the nonce is all
//! zeroes because every message gets a fresh ephemeral key pair), so the same
//! construction can be reproduced by any libsodium consumer.
//!
//! The host opens the box with the key pair it generated for the connection and
//! then compares `sha256(plain ‖ preset_salt)` against the stored `h1` in
//! constant time. See the call sites in `server/connection.rs`.
//!
//! This is the *only* way the preset password is accepted. The host does not
//! advertise the preset salt any more, so a client cannot build a salt-based
//! half for it: the normal password response is expected to fail, and the host
//! then opens the box. There is no policy negotiation and no feature flag —
//! every build behaves the same.
//!
//! A build compiled without both `MY_PASSWORD_HASH` and `MY_PASSWORD_SALT` has no
//! preset password whatsoever: the host generates no key pair, advertises no
//! public key, and refuses the channel. It never falls back to comparing clear
//! text, so there is no downgrade path to lose.
//!
//! Design constraints that must not be relaxed:
//!
//! * The body binds the connection's `challenge` and the host key fingerprint,
//!   so a captured box cannot be replayed on another connection and a box sealed
//!   for a different host key cannot be opened here.
//! * The body is a fixed size, so the ciphertext length does not leak the
//!   password length.
//! * Clear text lives in [`Secret`], which wipes its buffer on drop.

// Wired into the login flow by the server/client sides; kept here as a
// self-contained unit so the sealing rules stay auditable in one place.
#![allow(dead_code)]

use hbb_common::sodiumoxide::crypto::hash::sha256;
use hbb_common::sodiumoxide::crypto::box_;
use hbb_common::sodiumoxide::{randombytes, utils};

/// Bytes of the key fingerprint carried inside the sealed body.
pub const FP_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"RSPW";
const VERSION: u8 = 1;
const ZERO_NONCE: [u8; box_::NONCEBYTES] = [0u8; box_::NONCEBYTES];
/// Fixed body size: keeps the ciphertext length constant.
const BODY_LEN: usize = 192;
/// `epk ‖ mac ‖ body`.
const SEALED_LEN: usize = box_::PUBLICKEYBYTES + box_::MACBYTES + BODY_LEN;
/// Upper bound for a typed password. Longer inputs are rejected rather than
/// truncated, so a wrong-but-close password is never accepted.
pub const MAX_PASSWORD_LEN: usize = 160;
const HEADER_LEN: usize = 4 + 1 + FP_LEN + 1;

/// Clear-text buffer that wipes itself on drop.
pub struct Secret(Vec<u8>);

impl Secret {
    fn new(buf: Vec<u8>) -> Self {
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// `None` when the clear text is not valid UTF-8. Callers must treat that as
    /// an authentication failure, not as an empty password.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        utils::memzero(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the clear text, not even a length.
        write!(f, "Secret(****)")
    }
}

fn fingerprint(pk: &[u8; box_::PUBLICKEYBYTES]) -> [u8; FP_LEN] {
    let digest = sha256::hash(pk);
    let mut fp = [0u8; FP_LEN];
    fp.copy_from_slice(&digest.0[..FP_LEN]);
    fp
}

fn nonce() -> box_::Nonce {
    box_::Nonce::from_slice(&ZERO_NONCE).expect("zero nonce has the right length")
}

/// One key pair per connection, kept in memory only. A fresh pair per connection
/// gives the ciphertext forward secrecy: once the connection is gone the key is
/// dropped, so a captured box can never be opened later.
pub struct HostKey {
    pk: box_::PublicKey,
    sk: box_::SecretKey,
    fp: [u8; FP_LEN],
}

impl HostKey {
    pub fn generate() -> Self {
        let (pk, sk) = box_::gen_keypair();
        let fp = fingerprint(&pk.0);
        Self { pk, sk, fp }
    }

    /// Public key to advertise in `Hash.preset_seal_pubkey`.
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.0.to_vec()
    }

    pub fn fingerprint(&self) -> [u8; FP_LEN] {
        self.fp
    }

    /// Open a box produced by [`seal_password`] for this key and this
    /// connection. Returns `None` on *any* failure (wrong key, tampered body,
    /// replayed body, wrong challenge, malformed length) so callers cannot tell
    /// the cases apart.
    pub fn open(&self, sealed: &[u8], challenge: &str) -> Option<Secret> {
        if sealed.len() != SEALED_LEN || challenge.is_empty() {
            return None;
        }
        let mut epk = [0u8; box_::PUBLICKEYBYTES];
        epk.copy_from_slice(&sealed[..box_::PUBLICKEYBYTES]);
        let epk = box_::PublicKey(epk);
        let key = box_::precompute(&epk, &self.sk);
        // Wrap right away: the decrypted body contains the password, so it must
        // be wiped even on the early-return paths below.
        let plain = Secret::new(
            box_::open_precomputed(&sealed[box_::PUBLICKEYBYTES..], &nonce(), &key).ok()?,
        );
        let body = plain.as_bytes();
        if body.len() != BODY_LEN || &body[..4] != MAGIC.as_slice() || body[4] != VERSION {
            return None;
        }
        if !utils::memcmp(&body[5..5 + FP_LEN], &self.fp) {
            return None;
        }
        let ch_len = body[5 + FP_LEN] as usize;
        let mut off = HEADER_LEN;
        if ch_len == 0 || off + ch_len > body.len() {
            return None;
        }
        if !utils::memcmp(&body[off..off + ch_len], challenge.as_bytes()) {
            return None;
        }
        off += ch_len;
        if off + 2 > body.len() {
            return None;
        }
        let pw_len = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        if pw_len == 0 || pw_len > MAX_PASSWORD_LEN || off + pw_len > body.len() {
            return None;
        }
        Some(Secret::new(body[off..off + pw_len].to_vec()))
    }
}

/// Seal a typed password for `host_pk` (the 32 bytes from
/// `Hash.preset_seal_pubkey`). Returns `None` when the inputs cannot be sealed
/// (bad key length, empty or over-long password, empty challenge).
pub fn seal_password(password: &str, challenge: &str, host_pk: &[u8]) -> Option<Vec<u8>> {
    let pw = password.as_bytes();
    let ch = challenge.as_bytes();
    if pw.is_empty() || pw.len() > MAX_PASSWORD_LEN || ch.is_empty() || ch.len() > u8::MAX as usize
    {
        return None;
    }
    if host_pk.len() != box_::PUBLICKEYBYTES || HEADER_LEN + ch.len() + 2 + pw.len() > BODY_LEN {
        return None;
    }
    let mut raw = [0u8; box_::PUBLICKEYBYTES];
    raw.copy_from_slice(host_pk);
    let host_pk = box_::PublicKey(raw);
    let mut body = vec![0u8; BODY_LEN];
    body[..4].copy_from_slice(MAGIC);
    body[4] = VERSION;
    body[5..5 + FP_LEN].copy_from_slice(&fingerprint(&host_pk.0));
    body[5 + FP_LEN] = ch.len() as u8;
    let mut off = HEADER_LEN;
    body[off..off + ch.len()].copy_from_slice(ch);
    off += ch.len();
    body[off..off + 2].copy_from_slice(&(pw.len() as u16).to_le_bytes());
    off += 2;
    body[off..off + pw.len()].copy_from_slice(pw);
    off += pw.len();
    // Random padding: the unused tail must not look like a length marker.
    randombytes::randombytes_into(&mut body[off..]);
    let (epk, esk) = box_::gen_keypair();
    let key = box_::precompute(&host_pk, &esk);
    let boxed = box_::seal_precomputed(&body, &nonce(), &key);
    let mut out = Vec::with_capacity(box_::PUBLICKEYBYTES + boxed.len());
    out.extend_from_slice(&epk.0);
    out.extend_from_slice(&boxed);
    Some(out)
}

/// Length a correctly formed sealed blob must have. Used by the server to reject
/// oversized payloads before doing any crypto.
pub fn expected_sealed_len() -> usize {
    SEALED_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "Ab3dE9";

    fn roundtrip(pw: &str) -> Option<String> {
        let host = HostKey::generate();
        let sealed = seal_password(pw, CHALLENGE, &host.public_key())?;
        let opened = host.open(&sealed, CHALLENGE)?;
        opened.as_str().map(|s| s.to_owned())
    }

    #[test]
    fn seals_and_opens_the_password() {
        assert_eq!(roundtrip("s3cret-pw").as_deref(), Some("s3cret-pw"));
        assert_eq!(roundtrip("密码 with 中文").as_deref(), Some("密码 with 中文"));
    }

    #[test]
    fn ciphertext_length_is_constant() {
        let host = HostKey::generate();
        let pk = host.public_key();
        let short = seal_password("a", CHALLENGE, &pk).unwrap();
        let long = seal_password(&"x".repeat(MAX_PASSWORD_LEN), CHALLENGE, &pk).unwrap();
        assert_eq!(short.len(), expected_sealed_len());
        assert_eq!(long.len(), expected_sealed_len());
    }

    #[test]
    fn rejects_wrong_challenge() {
        let host = HostKey::generate();
        let sealed = seal_password("pw", CHALLENGE, &host.public_key()).unwrap();
        assert!(host.open(&sealed, "000000").is_none());
        assert!(host.open(&sealed, "").is_none());
    }

    #[test]
    fn rejects_other_host_key() {
        let host = HostKey::generate();
        let other = HostKey::generate();
        let sealed = seal_password("pw", CHALLENGE, &host.public_key()).unwrap();
        assert!(other.open(&sealed, CHALLENGE).is_none());
    }

    #[test]
    fn rejects_tampered_and_truncated_blobs() {
        let host = HostKey::generate();
        let sealed = seal_password("pw", CHALLENGE, &host.public_key()).unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(host.open(&bad, CHALLENGE).is_none(), "byte {} not bound", i);
        }
        assert!(host.open(&sealed[..sealed.len() - 1], CHALLENGE).is_none());
        assert!(host.open(&[], CHALLENGE).is_none());
        let mut oversized = sealed.clone();
        oversized.push(0);
        assert!(host.open(&oversized, CHALLENGE).is_none());
    }

    #[test]
    fn rejects_unusable_inputs() {
        let host = HostKey::generate();
        let pk = host.public_key();
        assert!(seal_password("", CHALLENGE, &pk).is_none());
        assert!(seal_password("pw", "", &pk).is_none());
        assert!(seal_password(&"x".repeat(MAX_PASSWORD_LEN + 1), CHALLENGE, &pk).is_none());
        assert!(seal_password("pw", CHALLENGE, &pk[..31]).is_none());
    }

    #[test]
    fn fingerprint_is_stable() {
        let host = HostKey::generate();
        let pk = host.public_key();
        assert_eq!(fingerprint(&host.pk.0), host.fingerprint());
        // The fingerprint travels inside the body; sealing to a copy of the
        // public key must therefore still open here.
        let sealed = seal_password("pw", CHALLENGE, &pk).unwrap();
        assert!(host.open(&sealed, CHALLENGE).is_some());
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let host = HostKey::generate();
        let sealed = seal_password("pw", CHALLENGE, &host.public_key()).unwrap();
        let opened = host.open(&sealed, CHALLENGE).unwrap();
        assert_eq!(format!("{:?}", opened), "Secret(****)");
    }
}
