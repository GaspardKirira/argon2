#include <argon2/argon2.hpp>
#include <iostream>
#include <string>

int main()
{
#if !defined(ARGON2_USE_REFERENCE) && !defined(ARGON2_CUSTOM_BACKEND)
  std::cout << "Argon2 backend not enabled.\n";
  std::cout << "Install libargon2 or define ARGON2_CUSTOM_BACKEND.\n";
  return 0;
#endif

  try
  {
    const std::string password = "super-password";

    std::string hash =
        argon2::hash_password_or_throw(password);

    std::cout << "Hash:\n"
              << hash << "\n";

    bool ok =
        argon2::verify_password_or_throw(password, hash);

    std::cout << "Verification: "
              << (ok ? "OK" : "FAIL") << "\n";
  }
  catch (const argon2::argon2_error &e)
  {
    std::cerr << "Argon2 error: "
              << e.what() << "\n";
    return 1;
  }

  return 0;
}
