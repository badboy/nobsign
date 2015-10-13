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

use ring::{digest, hmac};
use rustc_serialize::base64::{ToBase64, URL_SAFE};

#[derive(Debug,PartialEq)]
pub enum Error {
    BadData,
    BadSignature,
}

pub struct Signer {
    salt: String,
    separator: char,
    algorithm: &'static digest::Algorithm,
    secret: String,
}

// not really constant yet
fn constant_time_compare(left: &str, right: &str) -> bool {
    println!("left: {:?}, right: {:?}", left, right);
    left == right
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

        if constant_time_compare(&sig, &signature) {
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

#[test]
fn signs() {
    let signer = Signer::new("my-key".into());

    let signed = signer.sign("value");
    assert_eq!("value.EWkF3-80sipsPgLQ01NuTuPb0jQ".to_owned(),
               signed);

    assert_eq!("value".to_owned(),
               signer.unsign(&signed).unwrap());
}

#[test]
fn bad_unsign() {
    let signer = Signer::new("my-key".into());

    let signed = "value.ABCDEF";
    assert_eq!(Err(Error::BadSignature), signer.unsign(&signed));
}
