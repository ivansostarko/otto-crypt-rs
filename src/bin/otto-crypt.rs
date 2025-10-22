use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine as _};
use otto_crypt::{Otto, DEFAULT_CHUNK_SIZE};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("otto-crypt CLI
USAGE:
  otto-crypt enc-str <b64rawkey32> <plaintext_utf8>
  otto-crypt dec-str <b64rawkey32> <b64header> <b64cipher_and_tag>
  otto-crypt enc-file <b64rawkey32> <in> <out> [chunk_bytes]
  otto-crypt dec-file <b64rawkey32> <in> <out>");
        bail!("missing args");
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "enc-str" => {
            let key_b64 = args.remove(0);
            let pt = args.remove(0);
            let key = decode32(&key_b64)?;
            let res = Otto::encrypt_string(pt.as_bytes(), &key)?;
            println!("HEADER_B64={}", general_purpose::STANDARD.encode(&res.header));
            println!("CIPHER_B64={}", general_purpose::STANDARD.encode(&res.cipher_and_tag));
        }
        "dec-str" => {
            let key_b64 = args.remove(0);
            let header_b64 = args.remove(0);
            let cipher_b64 = args.remove(0);
            let key = decode32(&key_b64)?;
            let header = general_purpose::STANDARD.decode(header_b64)?;
            let cipher = general_purpose::STANDARD.decode(cipher_b64)?;
            let pt = Otto::decrypt_string(&cipher, &header, &key)?;
            println!("{}", String::from_utf8_lossy(&pt));
        }
        "enc-file" => {
            let key_b64 = args.remove(0);
            let input = args.remove(0);
            let output = args.remove(0);
            let chunk = args
                .get(0)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(DEFAULT_CHUNK_SIZE);
            let key = decode32(&key_b64)?;
            Otto::encrypt_file(input, output, &key, chunk)?;
            println!("OK");
        }
        "dec-file" => {
            let key_b64 = args.remove(0);
            let input = args.remove(0);
            let output = args.remove(0);
            let key = decode32(&key_b64)?;
            Otto::decrypt_file(input, output, &key)?;
            println!("OK");
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}

fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(s)?;
    if v.len() != 32 {
        bail!("expected 32-byte base64 key");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
