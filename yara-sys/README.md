# yara-sys

[![Crates.io](https://img.shields.io/crates/v/yara-sys.svg)](https://crates.io/crates/yara-sys)
[![Documentation](https://docs.rs/yara-sys/badge.svg)](https://docs.rs/yara-sys)

Native bindings for the [Yara library from VirusTotal](https://github.com/VirusTotal/yara).
Only works with Yara 3.7 for now.

More documentation can be found on [the Yara's documentation](https://yara.readthedocs.io/en/v3.7.0/index.html).

## Features

By default, this crate use a pre-built bindings file for Yara 3.7,
but you can use the feature `bindgen` to use on-the-fly generated bindings.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
