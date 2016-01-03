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
#include "loghelpers.h"
#include <stringcast.h>


namespace ush = usvfs::shared;


std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<NTSTATUS> &status)
{
  if (status.data() == 0x00000000) {
    os << "ok";
  } else {
    os << "err " << std::hex << (int)status.data();
  }
  return os;
}


std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<PUNICODE_STRING> &str)
{
  try {
    // TODO this does not correctly support surrogate pairs since the size used here
    // is the number of 16-bit characters in the buffer whereas toNarrow expects the
    // actual number of characters. It will always underestimate though, so worst
    // case scenario we truncate the string
    if (str.data() == nullptr) {
      os << "<null>";
    } else {
      os << ush::string_cast<std::string>(str.data()->Buffer
                                          , ush::CodePage::UTF8
                                          , str.data()->Length / sizeof(WCHAR));
    }
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}


static void writeToStream(std::ostream &os, LPCWSTR str)
{
  if (str == nullptr) {
    os << "<null>";
  } else {
    os << ush::string_cast<std::string>(str, ush::CodePage::UTF8);
  }
}


std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<LPWSTR> &str)
{
  try {
    writeToStream(os, str.data());
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}


std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<LPCWSTR> &str)
{
  try {
    writeToStream(os, str.data());
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}

std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<std::wstring> &str)
{
  try {
    // TODO this does not correctly support surrogate pairs since the size used here
    // is the number of 16-bit characters in the buffer whereas toNarrow expects the
    // actual number of characters. It will always underestimate though, so worst
    // case scenario we truncate the string
    os << ush::string_cast<std::string>(str.data(), ush::CodePage::UTF8);
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}
