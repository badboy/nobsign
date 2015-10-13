# nobsign

A simple but effective sign library, written in Rust.

Ported from [nobi](https://github.com/cyx/nobi),
which itself is a port of [itsdangerous](http://pythonhosted.org/itsdangerous/).

# Possible use cases

* Creating an activation link for users
* Creating a password reset link

# Example:

```rust
use nobsign::Signer;
let signer = Signer::new("my secret".into());

// Let's say the user's ID is 101
let signed = signer.sign("101");

// You can now email this url to your users!
let url = format!("http://yoursite.com/activate/?key={}", signed);
```
