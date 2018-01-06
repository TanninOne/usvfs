#pragma once

#include <vector>
#include <string>
#include <filesystem>
#include <cstdio>

class TestFileSystem
{
public:
  static constexpr auto FILE_CONTENTS_PRINT_PREFIX = "== ";

  typedef std::experimental::filesystem::path path;
  typedef std::FILE FILE;

  static path current_directory();

  TestFileSystem(FILE* output);

  void set_output(FILE* output) { m_output = output; }

  // base path used to trim outputs (which is important so we can compare tests ran at different base paths)
  void set_basepath(const char* path) { m_basepath = real_path(path); }

  // returns the path relative to the base path
  path relative_path(path full_path);

  virtual const char* id() = 0;

  virtual path real_path(const char* abs_or_rel_path) = 0;

  struct FileInformation {
    std::wstring name;
    uint32_t attributes;
    uint64_t size;

    FileInformation(const std::wstring& iname, uint32_t iattributes, uint64_t isize)
      : name(iname), attributes(iattributes), size(isize)
    {}

    bool is_dir() const;
    bool is_file() const;
  };
  typedef std::vector<FileInformation> FileInfoList;

  virtual FileInfoList list_directory(const path& directory_path) = 0;

  virtual void create_path(const path& directory_path) = 0;

  virtual void read_file(const path& file_path) = 0;

  enum class write_mode { manual_truncate, truncate, create, overwrite, append };
  virtual void write_file(const path& file_path, const void* data, std::size_t size, bool add_new_line, write_mode mode, bool rw_access = false) = 0;

  virtual void delete_file(const path& file_path) = 0;

  virtual void rename_file(const path& source_path, const path& destination_path, bool replace_existing, bool allow_copy) = 0;

protected:
  FILE* output() { return m_output; }
  static const char* write_operation_name(write_mode mode);
  static const char* rename_operation_name(bool replace_existing, bool allow_copy);

public: // mainly for derived class (but also used by helper classes like SafeHandle so public)
  void print_operation(const char* operation, const path& target);
  void print_operation(const char* operation, const path& source, const path& target);
  void print_result(const char* operation, uint32_t result, bool with_last_error = false, const char* opt_arg = nullptr, bool hide_result = false);
  void print_error(const char* operation, uint32_t result, bool with_last_error = false, const char* opt_arg = nullptr);
  void print_write_success(const void* data, std::size_t size, std::size_t written);

private:
  FILE* m_output;
  path m_basepath;
};
