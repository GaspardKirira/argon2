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

  argon2::HashOptions opt{};
  opt.memory_kib = 1 << 16;
  opt.iterations = 3;
  opt.parallelism = 1;

  auto result = argon2::hash_password(password, opt);

  if (!result.ok)
  {
    std::cerr << "Hash error: " << result.error << "\n";
    return 1;
  }

  std::cout << "Argon2 hash:\n";
  std::cout << result.value << "\n";

  return 0;
}
