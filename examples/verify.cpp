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

  const std::string password = "my-secret-password";

  auto hash = argon2::hash_password(password);

  if (!hash.ok)
  {
    std::cerr << "Hash error: " << hash.error << "\n";
    return 1;
  }

  auto verify = argon2::verify_password(password, hash.value);

  if (verify.ok)
    std::cout << "Password verified\n";
  else
    std::cout << "Password verification failed\n";

  return 0;
}
