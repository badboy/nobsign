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
//! # Example:
//!
//! ```rust
//! use nobsign::Signer;
//! let signer = Signer::new("my secret".into());
//!
//! // Let's say the user's ID is 101
//! let signed = signer.sign("101");
//!
//! // You can now email this url to your users!
//! let url = format!("http://yoursite.com/activate/?key={}", signed);
//! ```
extern crate rustc_serialize;
extern crate ring;
extern crate constant_time_eq;
extern crate time;
extern crate byteorder;

// Use same EPOCH as nobi, the Ruby implementation
const EPOCH : i32 = 1293840000;

use ring::{digest, hmac};
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};
use constant_time_eq::constant_time_eq;
use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug,PartialEq)]
pub enum Error {
    BadData,
    BadSignature,
    BadTimeSignature,
    SignatureExpired,
}

pub struct Signer {
    salt: String,
    separator: char,
    algorithm: &'static digest::Algorithm,
    secret: String,
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
    pub fn new(secret: String) -> Signer {
        Signer {
            salt: "nobi.Signer".into(),
            separator: '.',
            algorithm: &digest::SHA1,
            secret: secret,
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

        let signature = self.signature(&value);

        if constant_time_eq(&sig.as_bytes(), &signature.as_bytes()) {
            return Ok(value.into());
        }

        Err(Error::BadSignature)
    }


    fn derive_key(&self) -> digest::Digest {
        let s_key = hmac::SigningKey::new(self.algorithm, &self.secret.as_bytes());
        hmac::sign(&s_key, &self.salt.as_bytes())
    }

    fn signature(&self, value: &str) -> String {
        let derived_key = self.derive_key();
        let s_key = hmac::SigningKey::new(&self.algorithm, derived_key.as_ref());
        let sig = hmac::sign(&s_key, value.as_bytes());

        sig.as_ref().to_base64(URL_SAFE)
    }
}

impl TimestampSigner {
    pub fn new(secret: String) -> TimestampSigner {
        TimestampSigner { signer: Signer::new(secret) }
    }

    fn get_timestamp(&self) -> i32 {
        let now = time::now_utc().to_timespec();
        now.sec as i32 - EPOCH
    }

    pub fn sign(&self, value: &str) -> String {
        let timestamp = self.get_timestamp();
        let timestamp = int_to_bytes(timestamp);
        let timestamp = timestamp.to_base64(URL_SAFE);
        let value = format!("{}{}{}", value, self.signer.separator, timestamp);

        format!("{}{}{}",
                value,
                self.signer.separator,
                &self.signature(&value))
    }

    pub fn unsign(&self, value: &str, max_age: u32) -> Result<String, Error> {
        let result = try!(self.signer.unsign(value));

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

        let timestamp = match timestamp.from_base64() {
            Err(_) => return Err(Error::BadTimeSignature),
            Ok(timestamp) => timestamp,
        };
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

#[test]
fn signs() {
    let signer = Signer::new("my-key".into());

    let signed = signer.sign("value");
    assert_eq!("value.EWkF3-80sipsPgLQ01NuTuPb0jQ".to_owned(), signed);

    assert_eq!("value".to_owned(), signer.unsign(&signed).unwrap());
}

#[test]
fn bad_unsign() {
    let signer = Signer::new("my-key".into());

    let signed = "value.ABCDEF";
    assert_eq!(Err(Error::BadSignature), signer.unsign(&signed));
}

#[test]
fn signs_with_timestamp() {
    let signer = TimestampSigner::new("my-key".into());

    let signed = signer.sign("value");

    assert_eq!("value".to_owned(), signer.unsign(&signed, 100).unwrap());
}

#[test]
fn bad_unsign_with_timestamp() {

    let signer = TimestampSigner::new("my-key".into());

    let signed = "value.ABCDEF";
    assert_eq!(Err(Error::BadSignature), signer.unsign(&signed, 10));

    let signed = "value.EWkF3-80sipsPgLQ01NuTuPb0jQ";
    assert_eq!(Err(Error::BadTimeSignature), signer.unsign(&signed, 10));

    let signed = "value.AB.HHdWpuF7QVDZ_02wvECHvtV8vIc";
    assert_eq!(Err(Error::BadTimeSignature), signer.unsign(&signed, 10));
}

#[test]
fn unsign_expired() {
    use std::thread::sleep_ms;
    let signer = TimestampSigner::new("my-key".into());
    let signed = signer.sign("value");
    sleep_ms(1000);
    assert_eq!(Err(Error::SignatureExpired), signer.unsign(&signed, 0));
}
