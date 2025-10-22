# otto-crypt (Rust)

Rust implementation of the OTTO algorithm (AES-256-GCM + HKDF nonces) compatible with the Laravel/PHP SDK.

## Build
```bash
cargo build
```

## CLI examples
```bash
# create a 32-byte key
openssl rand -out key.bin 32
BASE64=$(base64 -w0 key.bin)

# encrypt a string
cargo run --bin otto-crypt -- enc-str "$BASE64" "Hello from Rust"

# encrypt / decrypt a file
cargo run --bin otto-crypt -- enc-file "$BASE64" input.mp4 output.mp4.otto
cargo run --bin otto-crypt -- dec-file "$BASE64" output.mp4.otto output.mp4
```
