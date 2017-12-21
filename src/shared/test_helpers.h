#pragma once

#include <filesystem>

namespace test {

  using std::experimental::filesystem::path;

  // path functions assume they are called by a test executable
  // (calculate the requested path relative to the current executable path)

  path path_of_test_bin(path relative_ = path());
  path path_of_test_temp(path relative_ = path());
  path path_of_usvfs_lib(path relative_ = path());

  std::string platform_dependant_executable(const char* name_, const char* ext_ = "exe", const char* platform_ = nullptr);
};