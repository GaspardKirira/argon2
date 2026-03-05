/**
 * @file argon2.hpp
 * @brief Minimal Argon2 password hashing and verification wrapper for C++.
 *
 * `argon2` provides a small, deterministic API for hashing and verifying passwords
 * using the PHC string format (recommended storage format), for example:
 *
 *   $argon2id$v=19$m=65536,t=3,p=1$<salt_b64>$<hash_b64>
 *
 * Scope:
 * - Generate random salts and encode them in PHC strings
 * - Hash passwords with configurable Argon2 parameters
 * - Verify passwords against an existing PHC Argon2 hash string
 * - Constant-time string comparison helper for verification
 *
 * Backends:
 * This library is a wrapper and can use one of the following backends:
 *
 * 1) Reference argon2 library backend:
 *    - Define ARGON2_USE_REFERENCE before including this header.
 *    - Requires the Argon2 C library headers and linking with argon2.
 *    - On Linux this is commonly: -largon2
 *
 * 2) Custom backend (portable):
 *    - Define ARGON2_CUSTOM_BACKEND and provide:
 *        bool argon2_custom_hash(std::string_view password,
 *                                const struct argon2::HashOptions &opt,
 *                                std::string &out_phc,
 *                                std::string &out_err);
 *
 *        bool argon2_custom_verify(std::string_view password,
 *                                  std::string_view existing_phc,
 *                                  bool &out_ok,
 *                                  std::string &out_err);
 *
 * Randomness:
 * - By default, salt generation uses std::random_device as a best-effort source.
 * - For better control, define ARGON2_CUSTOM_RANDOM and provide:
 *     bool argon2_custom_random_bytes(std::uint8_t *dst, std::size_t n);
 *
 * Non-goals (intentionally minimal):
 * - No user database integration
 * - No password policy enforcement
 * - No pepper management
 * - No KDF alternatives (bcrypt, scrypt)
 *
 * Security notes:
 * - Prefer Argon2id for password hashing.
 * - Memory cost should be as high as your latency budget allows.
 * - Always store the full PHC string as returned by hash_password().
 * - Never truncate the stored hash.
 *
 * Header-only. C++17+.
 */

#ifndef ARGON2_ARGON2_HPP
#define ARGON2_ARGON2_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(ARGON2_USE_REFERENCE)
// Requires the Argon2 reference library headers (argon2.h) and linking with -largon2
#include <argon2.h>
#endif

namespace argon2
{
  /**
   * @brief Exception type thrown by argon2 helpers when using throwing APIs.
   */
  class argon2_error : public std::runtime_error
  {
  public:
    explicit argon2_error(const std::string &msg) : std::runtime_error(msg) {}
  };

  /**
   * @brief Argon2 variant.
   *
   * For passwords, prefer Argon2id.
   */
  enum class Variant
  {
    Argon2d,
    Argon2i,
    Argon2id
  };

  /**
   * @brief Options for hashing a password.
   *
   * Units:
   * - memory_kib: KiB (not bytes)
   * - iterations: time cost
   * - parallelism: lanes/threads parameter
   */
  struct HashOptions
  {
    Variant variant = Variant::Argon2id;

    std::uint32_t memory_kib = 65536; ///< memory cost in KiB (example: 65536 = 64 MiB)
    std::uint32_t iterations = 3;     ///< time cost
    std::uint32_t parallelism = 1;    ///< parallelism parameter (lanes)

    std::size_t salt_len = 16; ///< salt length in bytes (typical: 16)
    std::size_t hash_len = 32; ///< output hash length in bytes (typical: 32)

    std::uint32_t version = 19; ///< Argon2 version, 19 is v1.3 (default)
  };

  /**
   * @brief Result for non-throwing APIs.
   */
  struct Result
  {
    bool ok = false;
    std::string value; ///< resulting PHC string for hash ops, or extra info
    std::string error; ///< error message
  };

  /**
   * @brief Constant-time string equality (best-effort) for verification.
   *
   * @note This compares full strings without early exit. Still depends on compiler behavior.
   */
  inline bool constant_time_equals(std::string_view a, std::string_view b)
  {
    if (a.size() != b.size())
      return false;

    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
      diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
  }

  /**
   * @brief Validate options are in a reasonable range (best-effort).
   *
   * This is not a full security policy, just sanity checks.
   */
  inline bool is_reasonable(const HashOptions &opt)
  {
    if (opt.salt_len < 8 || opt.salt_len > 64)
      return false;
    if (opt.hash_len < 16 || opt.hash_len > 128)
      return false;
    if (opt.iterations < 1 || opt.iterations > 1000)
      return false;
    if (opt.parallelism < 1 || opt.parallelism > 255)
      return false;
    if (opt.memory_kib < 8 * opt.parallelism) // reference library constraint: memory >= 8 * lanes
      return false;
    if (!(opt.version == 16 || opt.version == 19))
      return false;
    return true;
  }

  /**
   * @brief Generate random bytes (salt).
   */
  inline bool random_bytes(std::uint8_t *dst, std::size_t n)
  {
#if defined(ARGON2_CUSTOM_RANDOM)
    return argon2_custom_random_bytes(dst, n);
#else
    try
    {
      std::random_device rd;
      for (std::size_t i = 0; i < n; ++i)
        dst[i] = static_cast<std::uint8_t>(rd() & 0xFF);
      return true;
    }
    catch (...)
    {
      return false;
    }
#endif
  }

  /**
   * @brief Generate a random salt of length opt.salt_len.
   */
  inline Result generate_salt(const HashOptions &opt)
  {
    Result r{};

    if (!is_reasonable(opt))
    {
      r.ok = false;
      r.error = "argon2: invalid hashing options";
      return r;
    }

    std::vector<std::uint8_t> salt(opt.salt_len);
    if (!random_bytes(salt.data(), salt.size()))
    {
      r.ok = false;
      r.error = "argon2: failed to generate random salt bytes";
      return r;
    }

    r.ok = true;
    r.value.assign(reinterpret_cast<const char *>(salt.data()), salt.size()); // raw bytes
    return r;
  }

  /**
   * @brief Hash a password and return a PHC string.
   *
   * @param password plaintext password
   * @param opt hashing options
   * @return Result.value is the PHC string on success
   */
  inline Result hash_password(std::string_view password, const HashOptions &opt = {});

  /**
   * @brief Verify a password against an existing PHC Argon2 hash string.
   *
   * @param password plaintext password
   * @param existing_phc stored PHC string
   * @return Result.ok is true if verified, false otherwise. Result.error is set for parse/backend failures.
   */
  inline Result verify_password(std::string_view password, std::string_view existing_phc);

  /**
   * @brief Throwing variant of hash_password().
   */
  inline std::string hash_password_or_throw(std::string_view password, const HashOptions &opt = {})
  {
    auto r = hash_password(password, opt);
    if (!r.ok)
      throw argon2_error(r.error);
    return r.value;
  }

  /**
   * @brief Throwing variant of verify_password().
   */
  inline bool verify_password_or_throw(std::string_view password, std::string_view existing_phc)
  {
    auto r = verify_password(password, existing_phc);
    if (!r.error.empty() && !r.ok)
      throw argon2_error(r.error);
    return r.ok;
  }

  // ----------------------------
  // detail
  // ----------------------------
  namespace detail
  {
    // PHC uses standard Base64 without padding in most implementations.
    // Alphabet: A-Z a-z 0-9 + /
    inline constexpr const char *b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline int b64_index(unsigned char c)
    {
      if (c >= 'A' && c <= 'Z')
        return c - 'A';
      if (c >= 'a' && c <= 'z')
        return 26 + (c - 'a');
      if (c >= '0' && c <= '9')
        return 52 + (c - '0');
      if (c == '+')
        return 62;
      if (c == '/')
        return 63;
      return -1;
    }

    inline std::string b64_encode_no_pad(const std::uint8_t *data, std::size_t n)
    {
      std::string out;
      out.reserve(((n + 2) / 3) * 4);

      std::size_t i = 0;
      while (i + 3 <= n)
      {
        const std::uint32_t v =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (static_cast<std::uint32_t>(data[i + 1]) << 8) |
            (static_cast<std::uint32_t>(data[i + 2]));
        i += 3;

        out.push_back(b64[(v >> 18) & 0x3F]);
        out.push_back(b64[(v >> 12) & 0x3F]);
        out.push_back(b64[(v >> 6) & 0x3F]);
        out.push_back(b64[v & 0x3F]);
      }

      const std::size_t rem = n - i;
      if (rem == 1)
      {
        const std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(b64[(v >> 18) & 0x3F]);
        out.push_back(b64[(v >> 12) & 0x3F]);
        // no padding, omit last two chars
      }
      else if (rem == 2)
      {
        const std::uint32_t v =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(b64[(v >> 18) & 0x3F]);
        out.push_back(b64[(v >> 12) & 0x3F]);
        out.push_back(b64[(v >> 6) & 0x3F]);
        // no padding, omit last char
      }

      return out;
    }

    inline bool b64_decode_no_pad(std::string_view s, std::vector<std::uint8_t> &out, std::string &err)
    {
      out.clear();
      err.clear();

      if (s.empty())
        return true;

      // Valid lengths for unpadded base64 are: mod 4 in {0,2,3}
      const std::size_t mod = s.size() % 4;
      if (!(mod == 0 || mod == 2 || mod == 3))
      {
        err = "argon2: invalid base64 length";
        return false;
      }

      out.reserve((s.size() / 4) * 3 + 3);

      std::size_t i = 0;
      while (i + 4 <= s.size())
      {
        const int a = b64_index(static_cast<unsigned char>(s[i]));
        const int b = b64_index(static_cast<unsigned char>(s[i + 1]));
        const int c = b64_index(static_cast<unsigned char>(s[i + 2]));
        const int d = b64_index(static_cast<unsigned char>(s[i + 3]));
        if (a < 0 || b < 0 || c < 0 || d < 0)
        {
          err = "argon2: invalid base64 character";
          return false;
        }

        const std::uint32_t v =
            (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12) |
            (static_cast<std::uint32_t>(c) << 6) |
            (static_cast<std::uint32_t>(d));

        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        i += 4;
      }

      const std::size_t rem = s.size() - i;
      if (rem == 2)
      {
        const int a = b64_index(static_cast<unsigned char>(s[i]));
        const int b = b64_index(static_cast<unsigned char>(s[i + 1]));
        if (a < 0 || b < 0)
        {
          err = "argon2: invalid base64 character";
          return false;
        }
        const std::uint32_t v =
            (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12);
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
      }
      else if (rem == 3)
      {
        const int a = b64_index(static_cast<unsigned char>(s[i]));
        const int b = b64_index(static_cast<unsigned char>(s[i + 1]));
        const int c = b64_index(static_cast<unsigned char>(s[i + 2]));
        if (a < 0 || b < 0 || c < 0)
        {
          err = "argon2: invalid base64 character";
          return false;
        }
        const std::uint32_t v =
            (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12) |
            (static_cast<std::uint32_t>(c) << 6);
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
      }

      return true;
    }

    inline const char *variant_to_name(Variant v)
    {
      switch (v)
      {
      case Variant::Argon2d:
        return "argon2d";
      case Variant::Argon2i:
        return "argon2i";
      case Variant::Argon2id:
        return "argon2id";
      default:
        return "argon2id";
      }
    }

#if defined(ARGON2_USE_REFERENCE)
    inline argon2_type variant_to_type(Variant v)
    {
      switch (v)
      {
      case Variant::Argon2d:
        return Argon2_d;
      case Variant::Argon2i:
        return Argon2_i;
      case Variant::Argon2id:
        return Argon2_id;
      default:
        return Argon2_id;
      }
    }
#endif

    inline bool looks_like_phc(std::string_view s)
    {
      // minimal check: must start with $argon2
      return s.size() >= 7 && s[0] == '$' && s.find("$argon2") == 0;
    }

  } // namespace detail

  // ----------------------------
  // public API impl
  // ----------------------------

  inline Result hash_password(std::string_view password, const HashOptions &opt)
  {
    Result r{};

    if (password.empty())
    {
      r.ok = false;
      r.error = "argon2: password is empty";
      return r;
    }

    if (!is_reasonable(opt))
    {
      r.ok = false;
      r.error = "argon2: invalid hashing options";
      return r;
    }

#if defined(ARGON2_CUSTOM_BACKEND)
    std::string out_phc;
    std::string err;
    if (!argon2_custom_hash(password, opt, out_phc, err))
    {
      r.ok = false;
      r.error = err.empty() ? "argon2: custom hash backend failed" : err;
      return r;
    }
    if (!detail::looks_like_phc(out_phc))
    {
      r.ok = false;
      r.error = "argon2: custom backend returned unexpected PHC format";
      return r;
    }
    r.ok = true;
    r.value = std::move(out_phc);
    return r;

#elif defined(ARGON2_USE_REFERENCE)
    std::vector<std::uint8_t> salt(opt.salt_len);
    if (!random_bytes(salt.data(), salt.size()))
    {
      r.ok = false;
      r.error = "argon2: failed to generate random salt bytes";
      return r;
    }

    // encoded length helper exists in reference library.
    // argon2_encodedlen expects memory in KiB.
    const std::size_t encoded_len = static_cast<std::size_t>(
        argon2_encodedlen(
            opt.iterations,
            opt.memory_kib,
            opt.parallelism,
            static_cast<uint32_t>(opt.salt_len),
            static_cast<uint32_t>(opt.hash_len),
            static_cast<argon2_type>(detail::variant_to_type(opt.variant))));

    std::string encoded;
    encoded.resize(encoded_len);

    std::vector<std::uint8_t> hash(opt.hash_len);

    const argon2_type t = detail::variant_to_type(opt.variant);

    const int rc = argon2_hash(
        opt.iterations,
        opt.memory_kib,
        opt.parallelism,
        password.data(), password.size(),
        salt.data(), salt.size(),
        hash.data(), hash.size(),
        encoded.data(), encoded.size(),
        static_cast<argon2_version>(opt.version),
        t);

    if (rc != ARGON2_OK)
    {
      r.ok = false;
      r.error = std::string("argon2: reference backend failed: ") + argon2_error_message(rc);
      return r;
    }

    // encoded is null-terminated by argon2_hash, trim to C string length
    encoded.resize(std::char_traits<char>::length(encoded.c_str()));

    if (!detail::looks_like_phc(encoded))
    {
      r.ok = false;
      r.error = "argon2: reference backend returned unexpected PHC format";
      return r;
    }

    r.ok = true;
    r.value = std::move(encoded);
    return r;

#else
    r.ok = false;
    r.error = "argon2: no backend enabled (define ARGON2_USE_REFERENCE or ARGON2_CUSTOM_BACKEND)";
    return r;
#endif
  }

  inline Result verify_password(std::string_view password, std::string_view existing_phc)
  {
    Result r{};

    if (password.empty())
    {
      r.ok = false;
      r.error = "argon2: password is empty";
      return r;
    }

    if (!detail::looks_like_phc(existing_phc))
    {
      r.ok = false;
      r.error = "argon2: invalid PHC string format";
      return r;
    }

#if defined(ARGON2_CUSTOM_BACKEND)
    bool ok = false;
    std::string err;
    if (!argon2_custom_verify(password, existing_phc, ok, err))
    {
      r.ok = false;
      r.error = err.empty() ? "argon2: custom verify backend failed" : err;
      return r;
    }
    r.ok = ok;
    if (!ok)
      r.value = "mismatch";
    return r;

#elif defined(ARGON2_USE_REFERENCE)
    // Determine type from prefix (argon2d, argon2i, argon2id)
    argon2_type t = Argon2_id;
    if (existing_phc.find("$argon2d$") == 0)
      t = Argon2_d;
    else if (existing_phc.find("$argon2i$") == 0)
      t = Argon2_i;
    else if (existing_phc.find("$argon2id$") == 0)
      t = Argon2_id;
    else
    {
      r.ok = false;
      r.error = "argon2: unsupported variant in PHC string";
      return r;
    }

    const int rc = argon2_verify(
        existing_phc.data(),
        password.data(),
        password.size(),
        t);

    if (rc == ARGON2_OK)
    {
      r.ok = true;
      return r;
    }

    if (rc == ARGON2_VERIFY_MISMATCH)
    {
      r.ok = false;
      r.value = "mismatch";
      return r;
    }

    r.ok = false;
    r.error = std::string("argon2: reference verify failed: ") + argon2_error_message(rc);
    return r;

#else
    r.ok = false;
    r.error = "argon2: no backend enabled (define ARGON2_USE_REFERENCE or ARGON2_CUSTOM_BACKEND)";
    return r;
#endif
  }

} // namespace argon2

#endif // ARGON2_ARGON2_HPP
