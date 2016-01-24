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
#include "logging.h"
#include "stringcast.h"


namespace ush = usvfs::shared;

namespace std {
ostream &operator<<(ostream &os, LPCWSTR str);
ostream &operator<<(ostream &os, LPWSTR str);
ostream &operator<<(ostream &os, const wstring &str);
}

std::ostream &std::operator<<(ostream &os, LPCWSTR str)
{

  try {
    // TODO this does not correctly support surrogate pairs since the size used here
    // is the number of 16-bit characters in the buffer whereas toNarrow expects the
    // actual number of characters.
    if (str == nullptr) {
      os << "<null>";
    } else {
      //os << ush::string_cast_impl<std::string, const wchar_t*>::cast(str, ush::CodePage::UTF8, 32);

      os << ush::string_cast<string>(str, ush::CodePage::UTF8);
    }
  } catch (const exception &e) {
    os << "ERR: " << e.what();
  }

  return os;
}

std::ostream &std::operator<<(ostream &os, const wstring &str)
{
  try {
    os << ush::string_cast<string>(str, ush::CodePage::UTF8);
  }
  catch (const exception &e) {
    os << "ERR: " << e.what();
  }

  return os;
}

std::ostream &std::operator<<(ostream &os, LPWSTR str)
{
  try {
    // TODO this does not correctly support surrogate pairs since the size used here
    // is the number of 16-bit characters in the buffer whereas toNarrow expects the
    // actual number of characters. It will always underestimate though, so worst
    // case scenario we truncate the string
    if (str == nullptr) {
      os << "<null>";
    } else {
      os << ush::string_cast<string>(str, ush::CodePage::UTF8);
    }
  } catch (const exception &e) {
    os << "ERR: " << e.what();
  }

  return os;
}

