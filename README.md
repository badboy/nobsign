# nobsign

A simple but effective sign library, written in Rust.

Ported from [nobi](https://github.com/cyx/nobi),
which itself is a port of [itsdangerous](http://pythonhosted.org/itsdangerous/).

## Documentation

[Online Documentation](http://badboy.github.io/nobsign/nobsign/).

## Possible use cases

* Creating an activation link for users
* Creating a password reset link

## Basic Example:

```rust
use nobsign::Signer;
let signer = Signer::new(b"my secret");

// Let's say the user's ID is 101
let signed = signer.sign("101");

// You can now email this url to your users!
let url = format!("http://yoursite.com/activate/?key={}", signed);

// Later check the signature and get the value back
let unsigned = signer.unsign(&signed).unwrap();
```

## Example with timestamped signatures

```rust
use nobsign::TimestampSigner;
let signer = TimestampSigner::new(b"my secret");

// Let's say the user's ID is 101
let signed = signer.sign("101");

// You can now email this url to your users!
let url = format!("http://yoursite.com/activate/?key={}", signed);

// In your code, you can verify the expiration:
signer.unsign(&signed, 86400).unwrap(); // 1 day expiration
```
