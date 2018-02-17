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


#include "dllimport.h"
#include <boost/current_function.hpp>
#include <sstream>
#include "shmlogger.h"
#include "stringutils.h"
#include "ntdll_declarations.h"

// TODO according to the standard (17.4.3.1) I shouldn't add these to std but if they are in global namespace
// the lookup seems to fail?
namespace std {
  ostream &operator<<(ostream &os, LPCWSTR str);
  ostream &operator<<(ostream &os, LPWSTR str);
  ostream &operator<<(ostream &os, const wstring &str);
}

namespace usvfs {

namespace log {

enum class DisplayStyle : uint8_t {
  Hex = 0x01
};


class CallLoggerDummy {
public:
  template <typename T>
  CallLoggerDummy &addParam(const char*, const T&, uint8_t style = 0) { return *this; }
};

class CallLogger {
public:
  explicit CallLogger(const char *function)
  {
    const char *namespaceend = strrchr(function, ':');
    if (namespaceend != nullptr) {
      function = namespaceend + 1;
    }
    m_Message << function;
  }
  ~CallLogger()
  {
    try {
      static std::shared_ptr<spdlog::logger> log = spdlog::get("hooks");
      log->debug("{}", m_Message.str());
    } catch (...) {
      // suppress all exceptions in destructor
    }
  }

  template <typename T>
  CallLogger &addParam(const char *name, const T &value, uint8_t style = 0);
private:
  template <typename T>
  void outputParam(std::ostream &stream, const T &value, std::false_type) {
    stream << value;
  }

  template <typename T>
  void outputParam(std::ostream &stream, const T &value, std::true_type) {
    if (value == nullptr) {
      stream << "<null>";
    } else {
      stream << value;
    }
  }
private:
  std::ostringstream m_Message;
};


template <typename T>
CallLogger &CallLogger::addParam(const char *name, const T &value, uint8_t style)
{
  static bool enabled = spdlog::get("hooks")->should_log(spdlog::level::debug);
  typedef std::underlying_type<DisplayStyle>::type DSType;
  if (enabled) {
    m_Message << " [" << name << "=";
    if (style & static_cast<DSType>(DisplayStyle::Hex)) {
      m_Message << std::hex;
    } else {
      m_Message << std::dec;
    }

    outputParam(m_Message, value, std::is_pointer<T>());

    m_Message << "]";
  }
  return *this;
}

/**
 * a small helper class to wrap any object. The whole point is to give us a way
 * to ensure our own operator<< is used in addParam calls
 */
template <typename T>
class Wrap {
public:
  explicit Wrap(const T &data) : m_Data(data) {}
  Wrap(Wrap<T> &&reference) : m_Data(std::move(reference.m_Data)) {}
  Wrap(const Wrap<T> &reference) = delete;
  Wrap<T> &operator=(const Wrap<T>& reference) = delete;
  const T &data() const { return m_Data; }
private:
  const T &m_Data;
};

template <typename T>
Wrap<T> wrap(const T &data) { return Wrap<T>(data); }


std::ostream &operator<<(std::ostream &os, const Wrap<LPSTR> &str);
std::ostream &operator<<(std::ostream &os, const Wrap<LPWSTR> &str);
std::ostream &operator<<(std::ostream &os, const Wrap<LPCSTR> &str);
std::ostream &operator<<(std::ostream &os, const Wrap<LPCWSTR> &str);
std::ostream &operator<<(std::ostream &os, const Wrap<std::wstring> &str);

std::ostream &operator<<(std::ostream &os, const Wrap<PUNICODE_STRING> &str);
std::ostream &operator<<(std::ostream &os, const Wrap<NTSTATUS> &status);
std::ostream &operator<<(std::ostream &os, const Wrap<DWORD> &value);


spdlog::level::level_enum ConvertLogLevel(LogLevel level);
LogLevel ConvertLogLevel(spdlog::level::level_enum level);

} // namespace log

} // namespace usvfs


// prefer the short variant of the function name, without signature.
// Fall back to the portable boost macro
#ifdef __FUNCTION__
#define __MYFUNC__ __FUNCTION__
#else
#define __MYFUNC__ BOOST_CURRENT_FUNCTION
#endif

#define LOG_CALL() usvfs::log::CallLogger(__MYFUNC__)
//#define LOG_CALL() usvfs::log::CallLoggerDummy()

#define PARAM(val) addParam(#val, val)
#define PARAMHEX(val) addParam(#val, val, static_cast<uint8_t>(usvfs::log::DisplayStyle::Hex))
#define PARAMWRAP(val) addParam(#val, usvfs::log::wrap(val))
