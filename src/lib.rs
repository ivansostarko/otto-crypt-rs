use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce, Tag,
};
use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

const MAGIC: &[u8; 5] = b"OTTO1";
const ALGO_ID: u8 = 0xA1;
const KDF_RAW: u8 = 0x02;
const FLAG_CHUNKED: u8 = 0x01;

const FIXED_HDR_LEN: usize = 11;
const FILE_SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;

#[derive(Clone)]
pub struct EncResult {
    pub header: Vec<u8>,
    pub cipher_and_tag: Vec<u8>,
}

pub struct Otto;

impl Otto {
    pub fn encrypt_string(plaintext: &[u8], raw_key32: &[u8; 32]) -> Result<EncResult> {
        let chunked = false;
        let (header, aad, enc_key, nonce_key) = init_ctx_raw(raw_key32, chunked)?;
        let nonce = hkdf_chunk_nonce(&nonce_key, 0)?;
        let mut cipher = plaintext.to_vec();
        let tag = encrypt_in_place(&enc_key, &nonce, &aad, &mut cipher)?;
        let mut cipher_and_tag = cipher;
        cipher_and_tag.extend_from_slice(tag.as_slice());
        Ok(EncResult { header, cipher_and_tag })
    }

    pub fn decrypt_string(cipher_and_tag: &[u8], header: &[u8], raw_key32: &[u8; 32]) -> Result<Vec<u8>> {
        let (_hdr, aad, enc_key, nonce_key) = init_ctx_from_header(header, raw_key32)?;
        let nonce = hkdf_chunk_nonce(&nonce_key, 0)?;
        if cipher_and_tag.len() < TAG_LEN {
            bail!("cipher too short");
        }
        let (ct, tag) = cipher_and_tag.split_at(cipher_and_tag.len() - TAG_LEN);
        let mut plaintext = ct.to_vec();
        decrypt_in_place(&enc_key, &nonce, &aad, &mut plaintext, tag)?;
        Ok(plaintext)
    }

    pub fn encrypt_file<P: AsRef<Path>>(input: P, output: P, raw_key32: &[u8; 32], chunk_size: usize) -> Result<()> {
        let chunked = true;
        let (header, aad, enc_key, nonce_key) = init_ctx_raw(raw_key32, chunked)?;
        let mut fin = File::open(input)?;
        let mut fout = File::create(output)?;
        fout.write_all(&header)?;

        let mut buf = vec![0u8; chunk_size];
        let mut counter: u64 = 0;
        loop {
            let n = fin.read(&mut buf)?;
            if n == 0 { break; }
            let nonce = hkdf_chunk_nonce(&nonce_key, counter)?;
            counter += 1;

            let mut ct = buf[..n].to_vec();
            let tag = encrypt_in_place(&enc_key, &nonce, &aad, &mut ct)?;

            let len_be = (ct.len() as u32).to_be_bytes();
            fout.write_all(&len_be)?;
            fout.write_all(&ct)?;
            fout.write_all(tag.as_slice())?;
        }
        fout.flush()?;
        Ok(())
    }

    pub fn decrypt_file<P: AsRef<Path>>(input: P, output: P, raw_key32: &[u8; 32]) -> Result<()> {
        let mut fin = File::open(input)?;
        let mut fixed = [0u8; FIXED_HDR_LEN];
        fin.read_exact(&mut fixed)?;
        validate_fixed_header(&fixed)?;
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;

        let mut var_part = vec![0u8; var_len];
        fin.read_exact(&mut var_part)?;

        let mut header = fixed.to_vec();
        header.extend_from_slice(&var_part);

        let (_hdr, aad, enc_key, nonce_key) = init_ctx_from_header(&header, raw_key32)?;

        let mut fout = File::create(output)?;
        let mut counter: u64 = 0;

        loop {
            let mut len_be = [0u8; 4];
            match fin.read_exact(&mut len_be) {
                Ok(()) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    } else {
                        return Err(e.into());
                    }
                }
            }
            let clen = u32::from_be_bytes(len_be) as usize;
            if clen == 0 { break; }

            let mut ct = vec![0u8; clen];
            fin.read_exact(&mut ct)?;
            let mut tag = [0u8; TAG_LEN];
            fin.read_exact(&mut tag)?;

            let nonce = hkdf_chunk_nonce(&nonce_key, counter)?;
            counter += 1;

            let mut pt = ct;
            decrypt_in_place(&enc_key, &nonce, &aad, &mut pt, &tag)?;
            fout.write_all(&pt)?;
        }
        fout.flush()?;
        Ok(())
    }

    pub fn x25519_generate() -> (Vec<u8>, Vec<u8>) {
        let sk = X25519Secret::new(OsRng);
        let pk = X25519Public::from(&sk);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    pub fn x25519_shared(my_secret32: &[u8; 32], their_public32: &[u8; 32]) -> Vec<u8> {
        let sk = X25519Secret::from(*my_secret32);
        let pk = X25519Public::from(*their_public32);
        sk.diffie_hellman(&pk).to_bytes().to_vec()
    }

    pub fn hkdf_session(shared: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), shared);
        let mut okm = [0u8; 32];
        hk.expand(b"OTTO-P2P-SESSION", &mut okm)
            .map_err(|_| anyhow!("HKDF expand failed"))?;
        Ok(okm)
    }
}

fn init_ctx_raw(raw_key32: &[u8; 32], chunked: bool) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
    let mut file_salt = [0u8; FILE_SALT_LEN];
    OsRng.fill_bytes(&mut file_salt);

    let flags = if chunked { FLAG_CHUNKED } else { 0x00 };
    let var_part = file_salt.to_vec();
    let var_len_be = (var_part.len() as u16).to_be_bytes();

    let mut header = Vec::with_capacity(FIXED_HDR_LEN + var_part.len());
    header.extend_from_slice(MAGIC);
    header.push(ALGO_ID);
    header.push(KDF_RAW);
    header.push(flags);
    header.push(0x00);
    header.extend_from_slice(&var_len_be);
    header.extend_from_slice(&var_part);

    let (enc_key, nonce_key) = derive_enc_and_nonce_keys(raw_key32, &file_salt)?;
    let aad = header.clone();
    Ok((header, aad, enc_key, nonce_key))
}

fn init_ctx_from_header(header: &[u8], raw_key32: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
    if header.len() < FIXED_HDR_LEN {
        bail!("header too short");
    }
    validate_fixed_header(&header[..FIXED_HDR_LEN])?;
    let var_len = u16::from_be_bytes([header[9], header[10]]) as usize;
    if header.len() != FIXED_HDR_LEN + var_len {
        bail!("header length mismatch");
    }
    let var_part = &header[FIXED_HDR_LEN..];
    if var_part.len() < FILE_SALT_LEN {
        bail!("missing file salt");
    }
    let file_salt = &var_part[..FILE_SALT_LEN];

    let (enc_key, nonce_key) = derive_enc_and_nonce_keys(raw_key32, file_salt)?;
    let aad = header.to_vec();
    Ok((header.to_vec(), aad, enc_key, nonce_key))
}

fn validate_fixed_header(fixed: &[u8]) -> Result<()> {
    if &fixed[0..5] != MAGIC { bail!("bad magic"); }
    if fixed[5] != ALGO_ID { bail!("algo mismatch"); }
    if fixed[6] != KDF_RAW { bail!("kdf mismatch (expected RAW)"); }
    Ok(())
}

fn derive_enc_and_nonce_keys(raw_key32: &[u8; 32], file_salt: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), raw_key32);
    let mut enc_key = [0u8; 32];
    hk.expand(b"OTTO-ENC-KEY", &mut enc_key)
        .map_err(|_| anyhow!("HKDF expand enc failed"))?;

    let hk2 = Hkdf::<Sha256>::new(Some(file_salt), raw_key32);
    let mut nonce_key = [0u8; 32];
    hk2.expand(b"OTTO-NONCE-KEY", &mut nonce_key)
        .map_err(|_| anyhow!("HKDF expand nonce failed"))?;

    Ok((enc_key, nonce_key))
}

fn hkdf_chunk_nonce(nonce_key: &[u8; 32], counter: u64) -> Result<[u8; NONCE_LEN]> {
    let mut ctr = [0u8; 8];
    ctr.copy_from_slice(&counter.to_be_bytes());
    let mut info = Vec::with_capacity(16 + 8);
    info.extend_from_slice(b"OTTO-CHUNK-NONCE");
    info.extend_from_slice(&ctr);

    let hk = Hkdf::<Sha256>::new(Some(&[]), nonce_key);
    let mut out = [0u8; NONCE_LEN];
    hk.expand(&info, &mut out).map_err(|_| anyhow!("HKDF expand nonce failed"))?;
    Ok(out)
}

fn encrypt_in_place(enc_key: &[u8; 32], nonce12: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<Tag> {
    let key = Key::<Aes256Gcm>::from_slice(enc_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce12);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok(tag)
}

fn decrypt_in_place(enc_key: &[u8; 32], nonce12: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<()> {
    let key = Key::<Aes256Gcm>::from_slice(enc_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce12);
    let tag = Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(())
}

pub fn zeroize_vec(v: &mut Vec<u8>) { v.zeroize(); }
