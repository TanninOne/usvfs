/*
Userspace Virtual Filesystem

Copyright (C) 2015 Sebastian Herbord. All rights reserved.

This file is part of usvfs.

usvfs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

usvfs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <string>
#include <ios>

#if 1
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#else
#include <filesystem>
namespace fs = std::tr2::sys;
#endif

namespace usvfs {

namespace shared {

void strncpy_sz(char *dest, const char *src, size_t destSize);
void wcsncpy_sz(wchar_t *dest, const wchar_t *src, size_t destSize);

bool startswith(const wchar_t *string, const wchar_t *subString);


// Return path when appended to a_From will resolve to same as a_To
fs::path make_relative(const fs::path &from, const fs::path &to);

std::string to_hex(void *bufferIn, size_t bufferSize);

///
/// \brief convert unicode string to upper-case (locale invariant)
/// \param input
/// \return
///
std::wstring to_upper(const std::wstring &input);

class FormatGuard {
  std::ostream &m_Stream;
  std::ios::fmtflags m_Flags;

public:
  FormatGuard(std::ostream &stream)
      : m_Stream(stream), m_Flags(stream.flags()) {}

  FormatGuard(const FormatGuard &reference) = delete;
  FormatGuard &operator=(FormatGuard &reference) = delete;

  ~FormatGuard() { m_Stream.flags(m_Flags); }
};

} // namespace shared

} // namespace usvfs
