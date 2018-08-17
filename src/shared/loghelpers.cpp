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
#include "stringcast.h"
#include "stringutils.h"


namespace ush = usvfs::shared;

std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<DWORD> &value)
{
  ush::FormatGuard guard(os);
  os << std::hex << value.data();
  return os;
}

std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<NTSTATUS> &status)
{
  switch (status.data()) {
    case 0x00000000: {
      os << "ok";
    } break;
    case 0xC0000022: {
      os << "access denied";
    } break;
    case 0xC0000035: {
      os << "exists already";
    } break;
    default: {
      ush::FormatGuard guard(os);
      os << "err " << std::hex << (int)status.data();
    } break;
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

static void writeToStream(std::ostream &os, LPCSTR str)
{
  if (str == nullptr) {
    os << "<null>";
  }
  else {
    os << str;
  }
}

static void writeToStream(std::ostream &os, LPCWSTR str)
{
  if (str == nullptr) {
    os << "<null>";
  } else {
    os << ush::string_cast<std::string>(str, ush::CodePage::UTF8);
  }
}

std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<LPSTR> &str)
{
  try {
    writeToStream(os, str.data());
  }
  catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}

std::ostream &usvfs::log::operator<<(std::ostream &os, const Wrap<LPCSTR> &str)
{
  try {
    writeToStream(os, str.data());
  }
  catch (const std::exception &e) {
    os << e.what();
  }

  return os;
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

spdlog::level::level_enum usvfs::log::ConvertLogLevel(LogLevel level)
{
  switch (level) {
    case LogLevel::Debug: return spdlog::level::debug;
    case LogLevel::Info: return spdlog::level::info;
    case LogLevel::Warning: return spdlog::level::warn;
    case LogLevel::Error: return spdlog::level::err;
    default: return spdlog::level::debug;
  }
}

LogLevel usvfs::log::ConvertLogLevel(spdlog::level::level_enum level)
{
  switch (level) {
    case spdlog::level::debug: return LogLevel::Debug;
    case spdlog::level::info:  return LogLevel::Info;
    case spdlog::level::warn:  return LogLevel::Warning;
    case spdlog::level::err:   return LogLevel::Error;
    default: return LogLevel::Debug;
  }
}

std::ostream &std::operator<<(ostream &os, LPCWSTR str)
{

  try {
    // TODO this does not correctly support surrogate pairs since the size used here
    // is the number of 16-bit characters in the buffer whereas toNarrow expects the
    // actual number of characters.
    if (str == nullptr) {
      os << "<null>";
    }
    else {
      //os << ush::string_cast_impl<std::string, const wchar_t*>::cast(str, ush::CodePage::UTF8, 32);

      os << ush::string_cast<string>(str, ush::CodePage::UTF8);
    }
  }
  catch (const exception &e) {
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
    }
    else {
      os << ush::string_cast<string>(str, ush::CodePage::UTF8);
    }
  }
  catch (const exception &e) {
    os << "ERR: " << e.what();
  }

  return os;
}

