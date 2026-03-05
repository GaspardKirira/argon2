#include <argon2/argon2.hpp>

#include <cassert>
#include <iostream>
#include <string>

static bool backend_available()
{
#if defined(ARGON2_USE_REFERENCE) || defined(ARGON2_CUSTOM_BACKEND)
  return true;
#else
  return false;
#endif
}

static void test_hash_and_verify()
{
  argon2::HashOptions opt{};
  opt.variant = argon2::Variant::Argon2id;
  opt.memory_kib = 1 << 16; // 65536 KiB = 64 MiB
  opt.iterations = 3;
  opt.parallelism = 1;
  opt.salt_len = 16;
  opt.hash_len = 32;
  opt.version = 19;

  const std::string password = "correct horse battery staple";

  auto h = argon2::hash_password(password, opt);
  assert(h.ok);
  assert(!h.value.empty());
  assert(h.value.rfind("$argon2", 0) == 0);

  auto ok = argon2::verify_password(password, h.value);
  assert(ok.ok);

  auto bad = argon2::verify_password("wrong password", h.value);
  assert(!bad.ok);
}

static void test_invalid_inputs()
{
  {
    auto r = argon2::hash_password("", argon2::HashOptions{});
    assert(!r.ok);
    assert(!r.error.empty());
  }

  {
    auto r = argon2::verify_password("pw", "not-a-phc-string");
    assert(!r.ok);
    assert(!r.error.empty());
  }

  {
    argon2::HashOptions opt{};
    opt.salt_len = 2; // too small
    auto r = argon2::hash_password("pw", opt);
    assert(!r.ok);
    assert(!r.error.empty());
  }
}

int main()
{
  if (!backend_available())
  {
    std::cout << "[argon2] SKIP: no backend enabled. Install libargon2 and/or enable ARGON2_USE_REFERENCE, or provide ARGON2_CUSTOM_BACKEND.\n";
    return 0; // test passes but clearly skipped
  }

  test_hash_and_verify();
  test_invalid_inputs();

  std::cout << "[argon2] basic tests: OK\n";
  return 0;
}
