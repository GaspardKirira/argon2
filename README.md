# argon2

Minimal Argon2 password hashing utilities for C++.

`argon2` provides a small deterministic toolkit for hashing and verifying
passwords using the Argon2 algorithm.

Header-only wrapper. Uses the Argon2 reference backend.

## Download

https://vixcpp.com/registry/pkg/gk/argon2

## Why Argon2?

Modern applications must store passwords securely.

Plain-text passwords or simple hashes such as MD5 or SHA1 are unsafe.

Argon2 is the winner of the Password Hashing Competition (PHC) and is
considered one of the most secure password hashing algorithms available today.

Argon2 improves security because it:

- uses a random salt
- is memory-hard
- resists GPU and ASIC attacks
- allows configurable memory and time costs
- supports multiple variants (`argon2d`, `argon2i`, `argon2id`)

Many Argon2 libraries require large frameworks or complex integrations.

`argon2` provides a minimal alternative.

It focuses strictly on:

- password hashing
- password verification
- PHC string generation

You plug it into your authentication system.

No framework required.

Just simple Argon2 helpers.

## Features

- Generate random salts
- Hash passwords using Argon2
- Verify passwords against PHC strings
- Configurable memory cost
- Configurable time cost
- Configurable parallelism
- Constant-time comparison helper
- Deterministic API
- Header-only wrapper

## Installation

### Using Vix Registry

```bash
vix add @gk/argon2
vix deps
```

### Manual

```bash
git clone https://github.com/Gaspardkirira/argon2.git
```

Add the `include/` directory to your project.

## Dependency

Requires C++17 or newer.

The library is header-only but relies on the Argon2 reference implementation.

On Linux systems this usually requires linking with:

- `-largon2`

Example build:

```bash
g++ example.cpp -largon2
```

If your platform does not provide the Argon2 library, you can implement a
custom backend by defining:

- `ARGON2_CUSTOM_BACKEND`

and providing your own hashing functions.

## Quick examples

### Hash a password

```cpp
#define ARGON2_USE_REFERENCE
#include <argon2/argon2.hpp>

int main()
{
    auto hash = argon2::hash_password("my_password");

    if (!hash.ok)
        return 1;

    std::string stored = hash.value;
}
```

### Verify a password

```cpp
#define ARGON2_USE_REFERENCE
#include <argon2/argon2.hpp>

int main()
{
    std::string stored_hash =
        "$argon2id$v=19$m=65536,t=3,p=1$........$........";

    auto result =
        argon2::verify_password("my_password", stored_hash);

    if (result.ok)
    {
        // password is valid
    }
}
```

### Configure hashing parameters

```cpp
#define ARGON2_USE_REFERENCE
#include <argon2/argon2.hpp>

int main()
{
    argon2::HashOptions opt;

    opt.memory_kib = 65536;  // 64 MB
    opt.iterations = 3;
    opt.parallelism = 1;

    auto hash =
        argon2::hash_password("password", opt);
}
```

## API overview

Main structures:

- `argon2::HashOptions`
- `argon2::Result`

Main helpers:

- `argon2::generate_salt()`
- `argon2::hash_password()`
- `argon2::verify_password()`

Throwing variants:

- `argon2::hash_password_or_throw()`
- `argon2::verify_password_or_throw()`

## Password hashing workflow

Typical password storage workflow:

1. User provides password
2. Generate Argon2 hash
3. Store hash in database

When user logs in:

1. Verify password against stored hash

Example stored hash:

`$argon2id$v=19$m=65536,t=3,p=1$abcdefghijklmnop$QRSTUVWXYZabcdef...`

The PHC string includes:

- algorithm
- version
- memory cost
- iteration count
- parallelism
- salt
- hashed password

## Complexity

| Operation | Time complexity |
|----------|-----------------|
| Salt generation | O(1) |
| Password hashing | O(memory × iterations) |
| Password verification | O(memory × iterations) |

Security parameters can be tuned depending on hardware.

Typical production values:

- memory: 64 MB
- iterations: 2-4
- parallelism: 1-2

Higher values increase security but also increase computation time.

## Design principles

- Deterministic behavior
- Minimal implementation
- Header-only simplicity
- Argon2 reference backend
- Predictable API

This library focuses strictly on Argon2 password hashing.

If you need:

- full authentication frameworks
- user management
- OAuth2
- OpenID Connect

Build them on top of this layer.

## Tests

Run:

```bash
vix build
vix test
```

Tests verify:

- salt generation
- password hashing
- password verification
- parameter validation

## License

MIT License\
Copyright (c) Gaspard Kirira

