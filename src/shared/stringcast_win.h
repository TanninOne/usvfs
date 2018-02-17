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

#include "stringcast.h"
#include "stringutils.h"
#include "windows_error.h"
#include "logging.h"
#include <type_traits>

namespace usvfs {
namespace shared {

UINT windowsCP(CodePage codePage);

template <>
class string_cast_impl<std::string, const wchar_t*> {
public:
  static std::string cast(const wchar_t * const &source, CodePage codePage, size_t sourceLength)
  {
    std::string result;

    if (sourceLength == std::numeric_limits<size_t>::max()) {
      sourceLength = wcslen(source);
    }

    if (sourceLength > 0) {
      // use utf8 or local 8-bit encoding depending on user choice
      UINT cp = windowsCP(codePage);
      // preflight to find out the required buffer size
      int outLength = WideCharToMultiByte(cp, 0, source, static_cast<int>(sourceLength),
                                          nullptr, 0, nullptr, nullptr);
      if (outLength == 0) {
        throw windows_error("string conversion failed");
      }
      result.resize(outLength);
      outLength = WideCharToMultiByte(cp, 0, source, static_cast<int>(sourceLength),
                                      &result[0], outLength, nullptr, nullptr);
      if (outLength == 0) {
        throw windows_error("string conversion failed");
      }
      // fix output string length (i.e. in case of unconvertible characters
      while (result[outLength - 1] == L'\0') {
        result.resize(--outLength);
      }
    }

    return result;
  }
};


template <>
class string_cast_impl<std::wstring, const char*> {
public:
  static std::wstring cast(const char * const &source, CodePage codePage, size_t sourceLength) {
    std::wstring result;

    if (sourceLength == std::numeric_limits<size_t>::max()) {
      sourceLength = strlen(source);
    }
    if (sourceLength > 0) {
      // use utf8 or local 8-bit encoding depending on user choice
      UINT cp = windowsCP(codePage);
      // preflight to find out the required source size
      int outLength = MultiByteToWideChar(cp, 0, source, static_cast<int>(sourceLength), &result[0], 0);
      if (outLength == 0) {
        throw windows_error("string conversion failed");
      }
      result.resize(outLength);
      outLength = MultiByteToWideChar(cp, 0, source, static_cast<int>(sourceLength), &result[0], outLength);
      if (outLength == 0) {
        throw windows_error("string conversion failed");
      }
      while (result[outLength - 1] == L'\0') {
        result.resize(--outLength);
      }
    }

    return result;
  }
};

template <>
class string_cast_impl<std::wstring, const wchar_t*> {
public:
  static std::wstring cast(const wchar_t * const &source, CodePage, size_t) {
    return std::wstring(source);
  }
};

}
}
