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
#include "unicodestring.h"
#include "windows_error.h"
#include "stringutils.h"
#include "stringcast.h"
#include "logging.h"
#include <fmt/format.h>
#include <spdlog.h>


namespace ush = usvfs::shared;

namespace usvfs {

UnicodeString::UnicodeString()
{
  m_Data.Length = m_Data.MaximumLength = 0;
  m_Data.Buffer = nullptr;
}


UnicodeString::UnicodeString(HANDLE fileHandle)
{
  setFromHandle(fileHandle);
}


UnicodeString::UnicodeString(LPCSTR string)
{
  m_Buffer.resize(strlen(string));
  memcpy(&m_Buffer[0], ush::string_cast<std::wstring>(string).c_str(), m_Buffer.size() * sizeof(WCHAR));
  update();
}


UnicodeString::UnicodeString(LPCWSTR string, size_t length)
{
  if (length == std::string::npos) {
    length = wcslen(string);
  }
  m_Buffer.resize(length);
  memcpy(&m_Buffer[0], string, length * sizeof(WCHAR));
  update();
}


size_t UnicodeString::size() const {
  return m_Buffer.size() > 0 ? m_Buffer.size() - 1 : 0;
}

void UnicodeString::resize(size_t minSize) {
  m_Buffer.resize(minSize);
}

UnicodeString &UnicodeString::appendPath(PUNICODE_STRING path) {
  if (path != nullptr) {
    if (size() > 0) {
      m_Buffer.pop_back(); // zero termination
      m_Buffer.push_back(L'\\');
    }
    m_Buffer.insert(m_Buffer.end(), path->Buffer,
                    path->Buffer + (path->Length / sizeof(WCHAR)));
    update();
  }
  return *this;
}

void UnicodeString::set(LPCWSTR path) {
  m_Buffer.clear();
  static wchar_t Preamble[] = LR"(\??\)";
  m_Buffer.insert(m_Buffer.end(), Preamble, Preamble + 4);
  m_Buffer.insert(m_Buffer.end(), path, path + wcslen(path));
  update();
}

void UnicodeString::update() {
  while ((m_Buffer.size() > 0) && (*m_Buffer.rbegin() == L'\0')) {
    m_Buffer.resize(m_Buffer.size() - 1);
  }
  m_Data.Length = static_cast<USHORT>(m_Buffer.size() * sizeof (WCHAR));
  m_Data.MaximumLength = static_cast<USHORT>(m_Buffer.capacity() * sizeof(WCHAR));
  m_Buffer.push_back(L'\0');
}

void UnicodeString::setFromHandle(HANDLE fileHandle)
{
/*
  std::unique_ptr<char> buf(new char[1024 * 1024]);

  if (GetFileInformationByHandleEx(fileHandle, FileNameInfo, buf.get(), 1024 * 1024) == 0) {
    spdlog::get("hooks")->info("failed: {}", GetLastError());
  } else {
    FILE_NAME_INFO *info = (FILE_NAME_INFO*)buf.get();
    info->FileName[info->FileNameLength] = L'\0';
    spdlog::get("hooks")->info("success: {}", ush::string_cast<std::string>((WCHAR*)info->FileName));
  }
*/

  if (m_Buffer.size() < 128) {
    m_Buffer.resize(128);
  }

  DWORD preserveLastError = GetLastError();

  DWORD res = GetFinalPathNameByHandleW(fileHandle, &m_Buffer[0],
                                        static_cast<DWORD>(m_Buffer.size()),
                                        FILE_NAME_NORMALIZED);
  if (res == 0) {
    m_Buffer.resize(0);
  } else if (res > m_Buffer.size()) {
    m_Buffer.resize(res);
    GetFinalPathNameByHandleW(fileHandle, &m_Buffer[0], res, FILE_NAME_NORMALIZED);
  }

  update();

  SetLastError(preserveLastError);

  /* This code would also work on Windows XP but requires access to non-public API
     * and tends to crash if the handle isn't ok
      PVOID fileObject;
      int res = ::ObReferenceObjectByHandle(fileHandle,
                      THREAD_ALL_ACCESS, nullptr, UserMode, &fileObject, nullptr);

      if (res == STATUS_SUCCESS) {
        int stringLength;
        res = ::ObQueryNameString(fileObject, nullptr, 0, &stringLength);

        m_Buffer.resize(stringLength);
        m_Data.Buffer = &m_Buffer[0];

        res = ::ObQueryNameString(fileObject, &m_Data,
                                  static_cast<int>(m_Buffer.size()), &stringLength);

        ::ObDereferenceObject(fileObject);
      }*/
}

UnicodeString::operator LPCWSTR() const {
  return m_Buffer.data();
}

UnicodeString::operator PUNICODE_STRING() {
  m_Data.Buffer = &m_Buffer[0];
  return &m_Data;
}


std::ostream &operator<<(std::ostream &os, const UnicodeString &str)
{
  try {
    if (str.size() == 0) {
      os << "<empty string>";
    } else {
      // TODO this does not correctly support surrogate pairs since the size used here
      // is the number of 16-bit characters in the buffer whereas toNarrow expects the
      // actual number of characters. It will always underestimate though, so worst
      // case scenario we truncate the string
      os << ush::string_cast<std::string>(&str.m_Buffer[0], ush::CodePage::UTF8, str.size());
    }
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}

}
