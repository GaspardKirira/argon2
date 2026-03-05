cmake_minimum_required(VERSION 3.20)
project(argon2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(argon2 INTERFACE)
add_library(argon2::argon2 ALIAS argon2)

target_include_directories(argon2 INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(argon2 INTERFACE /W4 /permissive-)
else()
  target_compile_options(argon2 INTERFACE -Wall -Wextra -Wpedantic)
endif()

# argon2 wrapper uses the Argon2 reference backend when ARGON2_USE_REFERENCE is enabled.
# On many Linux distros, Argon2 symbols live in libargon2 and must be linked explicitly.
if (UNIX AND NOT APPLE)
  include(CheckLibraryExists)
  check_library_exists(argon2 argon2_hash "" HAVE_LIBARGON2)

  if (HAVE_LIBARGON2)
    target_link_libraries(argon2 INTERFACE argon2)
    target_compile_definitions(argon2 INTERFACE ARGON2_USE_REFERENCE=1)
  else()
    # If libargon2 is not found, consumers can provide their own implementation
    # by defining ARGON2_CUSTOM_BACKEND and implementing the backend functions.
  endif()
endif()

include(CTest)
enable_testing()

add_executable(argon2_basic_test tests/test_basic.cpp)
target_link_libraries(argon2_basic_test PRIVATE argon2::argon2)
add_test(NAME argon2.basic COMMAND argon2_basic_test)
