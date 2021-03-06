//! A simple but effective sign library, written in Rust.
//!
//! Ported from [nobi](https://github.com/cyx/nobi),
//! which itself is a port of [itsdangerous](http://pythonhosted.org/itsdangerous/).
//!
//! # Possible use cases
//!
//! * Creating an activation link for users
//! * Creating a password reset link
//!
//! # Basic Example:
//!
//! ```rust
//! use nobsign::Signer;
//! let signer = Signer::new(b"my secret");
//!
//! // Let's say the user's ID is 101
//! let signed = signer.sign("101");
//!
//! // You can now email this url to your users!
//! let url = format!("http://yoursite.com/activate/?key={}", signed);
//!
//! // Later check the signature and get the value back
//! let unsigned = signer.unsign(&signed).unwrap();
//! ```
//!
//! # Example with timestamped signatures
//!
//! ```rust
//! use nobsign::TimestampSigner;
//! let signer = TimestampSigner::new(b"my secret");
//!
//! // Let's say the user's ID is 101
//! let signed = signer.sign("101");
//!
//! // You can now email this url to your users!
//! let url = format!("http://yoursite.com/activate/?key={}", signed);
//!
//! // In your code, you can verify the expiration:
//! signer.unsign(&signed, 86400).unwrap(); // 1 day expiration
//! ```
extern crate base64;
extern crate byteorder;
extern crate ring;

// Use same EPOCH as nobi, the Ruby implementation
const EPOCH: u64 = 1293840000;

use base64::URL_SAFE_NO_PAD;
use byteorder::{ByteOrder, LittleEndian};
use ring::{digest, hmac};

static ALGORITHM: &'static digest::Algorithm = &digest::SHA1;

#[derive(Debug, PartialEq)]
pub enum Error {
    BadData,
    BadSignature,
    BadTimeSignature,
    SignatureExpired,
}

pub struct Signer {
    separator: char,
    key: hmac::SigningKey,
}

pub struct TimestampSigner {
    signer: Signer,
}

fn int_to_bytes(n: i32) -> [u8; 4] {
    let mut out = [0; 4];

    LittleEndian::write_i32(&mut out, n);
    out
}
fn bytes_to_int(n: &[u8]) -> i32 {
    assert!(n.len() == 4);
    LittleEndian::read_i32(n)
}

impl Signer {
    pub fn new(secret: &[u8]) -> Signer {
        let initial_key = hmac::SigningKey::new(ALGORITHM, secret);
        let derived_key = hmac::sign(&initial_key, b"nobi.Signer");

        Signer {
            separator: '.',
            key: hmac::SigningKey::new(ALGORITHM, derived_key.as_ref()),
        }
    }

    pub fn sign(&self, value: &str) -> String {
        format!("{}{}{}", value, self.separator, &self.signature(value))
    }

    pub fn unsign(&self, value: &str) -> Result<String, Error> {
        let mut splitted = value.rsplitn(2, |c| c == self.separator);

        let sig = match splitted.next() {
            Some(val) => val,
            None => return Err(Error::BadSignature),
        };
        let value = match splitted.next() {
            Some(val) => val,
            None => return Err(Error::BadSignature),
        };

        let sig = base64::decode_config(sig, URL_SAFE_NO_PAD).map_err(|_| Error::BadSignature)?;
        hmac::verify_with_own_key(&self.key, value.as_bytes(), &sig)
            .map_err(|_| Error::BadSignature)?;

        Ok(value.into())
    }

    fn signature(&self, value: &str) -> String {
        let sig = hmac::sign(&self.key, value.as_bytes());
        base64::encode_config(sig.as_ref(), URL_SAFE_NO_PAD)
    }
}

impl TimestampSigner {
    pub fn new(secret: &[u8]) -> TimestampSigner {
        TimestampSigner {
            signer: Signer::new(secret),
        }
    }

    fn get_timestamp(&self) -> i32 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        (match now {
            Ok(dur) => dur,
            Err(err) => err.duration(),
        }
        .as_secs()
            - EPOCH) as i32
    }

    pub fn sign(&self, value: &str) -> String {
        let timestamp = self.get_timestamp();
        let timestamp = int_to_bytes(timestamp);
        let timestamp = base64::encode_config(&timestamp, URL_SAFE_NO_PAD);
        let value = format!("{}{}{}", value, self.signer.separator, timestamp);

        format!(
            "{}{}{}",
            value,
            self.signer.separator,
            &self.signature(&value)
        )
    }

    pub fn unsign(&self, value: &str, max_age: u32) -> Result<String, Error> {
        let result = self.signer.unsign(value)?;

        if !result.contains(self.signer.separator) {
            return Err(Error::BadTimeSignature);
        }

        let mut splitted = result.rsplitn(2, |c| c == self.signer.separator);

        let timestamp = match splitted.next() {
            Some(val) => val,
            None => return Err(Error::BadSignature),
        };
        let value = match splitted.next() {
            Some(val) => val,
            None => return Err(Error::BadSignature),
        };

        let timestamp = base64::decode_config(timestamp, URL_SAFE_NO_PAD)
            .map_err(|_| Error::BadTimeSignature)?;

        if timestamp.len() != 4 {
            return Err(Error::BadTimeSignature);
        }
        let timestamp = bytes_to_int(&timestamp);
        let age = self.get_timestamp() - timestamp;

        if age > max_age as i32 {
            return Err(Error::SignatureExpired);
        }

        Ok(value.into())
    }

    fn signature(&self, value: &str) -> String {
        self.signer.signature(value)
    }
}

#[cfg(test)]
mod test {
    use super::ALGORITHM;
    use super::*;

    #[test]
    fn signs() {
        let signer = Signer::new(b"my-key");

        let signed = signer.sign("value");
        assert_eq!("value.EWkF3-80sipsPgLQ01NuTuPb0jQ".to_owned(), signed);

        assert_eq!("value".to_owned(), signer.unsign(&signed).unwrap());
    }

    #[test]
    fn bad_unsign() {
        let signer = Signer::new(b"my-key");

        let signed = "value.ABCDEF";
        assert_eq!(Err(Error::BadSignature), signer.unsign(&signed));
    }

    #[test]
    fn signs_with_timestamp() {
        let signer = TimestampSigner::new(b"my-key");

        let signed = signer.sign("value");

        assert_eq!("value".to_owned(), signer.unsign(&signed, 100).unwrap());
    }

    #[test]
    fn bad_unsign_with_timestamp() {
        let signer = TimestampSigner::new(b"my-key");

        let signed = "value.ABCDEF";
        assert_eq!(Err(Error::BadSignature), signer.unsign(&signed, 10));

        let signed = "value.EWkF3-80sipsPgLQ01NuTuPb0jQ";
        assert_eq!(Err(Error::BadTimeSignature), signer.unsign(&signed, 10));

        let signed = "value.AB.HHdWpuF7QVDZ_02wvECHvtV8vIc";
        assert_eq!(Err(Error::BadTimeSignature), signer.unsign(&signed, 10));
    }

    #[test]
    fn unsign_expired() {
        use std::thread;
        use std::time::Duration;

        let signer = TimestampSigner::new(b"my-key");
        let signed = signer.sign("value");
        thread::sleep(Duration::from_secs(1));
        assert_eq!(Err(Error::SignatureExpired), signer.unsign(&signed, 0));
    }

    #[test]
    fn with_secure_secret() {
        use ring::rand::{SecureRandom, SystemRandom};
        let sys_rand = SystemRandom::new();
        let mut key = vec![0u8; ALGORITHM.output_len];
        sys_rand.fill(&mut key).unwrap();

        let signer = Signer::new(&key);
        let signed = signer.sign("Hello world!");

        assert_eq!("Hello world!", signer.unsign(&signed).unwrap());
    }
}
