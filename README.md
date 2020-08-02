# LessPass-OTP

[![Build Status](https://dev.azure.com/lolo--32/lesspass-otp/_apis/build/status/lesspass-otp-CI?branchName=master)](https://dev.azure.com/lolo--32/lesspass-otp/_build/latest?definitionId=1&branchName=test-azure-pipelines)
[![codecov](https://codecov.io/gh/lolo32/lesspass-otp/branch/master/graph/badge.svg)](https://codecov.io/gh/lolo32/lesspass-otp)

This crate can be used to generate password for any site, with only a master password,
a site name, a login and a counter. 

Generate TOTP or HOTP too.

All the generated password are derived from a master password,
__that you are the only one to know__,
a site url,
a username
and of course, because these parameters cannot be changed,
a counter to increment to change the password on the site.
It's possible to change the password length and the characters set to use
(lowercase, uppercase, numbers and/or symbols).

> ##### Note
> 
> _Support of Azure Pipelines is based from [crate-ci/azure-pipelines](https://github.com/crate-ci/azure-pipelines)._

## Examples

### Initialise the library

```rust
use lesspass_otp::{Algorithm, LessPass, Otp, Settings};
use lesspass_otp::charset::{LowerCase, Numbers, Symbols, UpperCase};

let master = LessPass::new("mY5ecr3!", Algorithm::SHA256)?;
```

### Check the master password is valid, with fingerprint

Can be printed publicly

```rust
let fingerprint = master.get_fingerprint(b"");
assert_eq!(fingerprint, [
        ("#24FE23", "fa-car"),
        ("#DB6D00", "fa-certificate"),
        ("#B66DFF", "fa-gbp")
]);
```

### Generate a password

```rust
// 16 chars, and lower + upper + number + symbol
let settings = Settings::default();
// 20 chars, and lower + upper + number
let settings = Settings::new(
    20,
    LowerCase::Using,
    UpperCase::Using,
    Numbers::Using,
    Symbols::NotUsing,
);

// Generate a password
let password = master.password("facebook.com", "test@example.com", 42, &settings)?;
assert_eq!(password, "BJwptmUpz2bEWHM9NA48");
```

### TOTP or HOTP

Retrieve the current token:

```rust
let otp_secret = b"gfE%Tgd56^&!gd$";
let otp = Otp::new(otp_secret, 6, Some(Algorithm::SHA512), Some(30), Some(0))?;
// Get token from timestamp (require [feature = "std_time"])
let token = otp.totp();
// Get token from predefined timestamp
let token = otp.totp_from_ts(1_234_567_890);
assert_eq!(token, "586893");
```

Encrypt the OTP secret before storing it in an unsecured media.

```rust
let encrypted = master.secret_totp("github.com", "test@example.com", otp_secret)?;
assert_eq!(encrypted, &[
        255, 37, 183, 103, 211, 97, 25, 139, 84, 212, 123,
        123, 188, 58, 183, 111, 25, 79, 163, 101, 255, 155,
        174, 184, 12, 99, 200, 15, 246, 37, 204, 108
]);
// Store the encrypted token, it cannot be recovered without master password,
// website and username
store_otp_secret(&encrypted);
```

Decrypt the previous encrypted secret.

```rust
let encrypted = retrieve_otp_secret();

// Wrong login information, secret cannot be retrieved
let wrong_decrypted = master.secret_totp("facebook.com", "test@example.com", &encrypted)?;
assert_ne!(encrypted.to_vec(), wrong_decrypted);
let master2 = LessPass::new("pass", Algorithm::SHA256)?;
let wrong_decrypted = master2.secret_totp("github.com", "test@example.com", &encrypted)?;
assert_ne!(encrypted.to_vec(), wrong_decrypted);

// Correct information
let decrypted = master.secret_totp("github.com", "test@example.com", &encrypted)?;
assert_eq!(decrypted, otp_secret);
```
