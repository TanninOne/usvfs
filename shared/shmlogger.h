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

#include "logging.h"
#include "windows_sane.h"
#include "shared_memory.h"
#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/format.hpp>
#include <atomic>
#include <spdlog.h>
#include <cstdint>

typedef boost::interprocess::message_queue_t<usvfs::shared::VoidPointerT> message_queue_interop;

namespace spdlog {
namespace sinks {
class shm_sink : public sink {
  message_queue_interop m_LogQueue;

  std::atomic<int> m_DroppedMessages;

public:
  shm_sink(const char *queueName);
  virtual void log(const details::log_msg &msg) override;
  void output(level::level_enum lev, const std::string &message);
  virtual void flush() override;
};
}
}


class SHMLogger {

public:
  static const size_t MESSAGE_COUNT = 1024;
  static const size_t MESSAGE_SIZE  = 512;

public:
  static SHMLogger &create(const char *instanceName);
  static SHMLogger &open(const char *instanceName);
  static void free();

  static bool isInstantiated() {
    return s_Instance != nullptr;
  }

  static inline SHMLogger &instance() {
    if (s_Instance == nullptr) {
      throw std::runtime_error("shm logger not instantiated");
    }
    return *s_Instance;
  }

  void log(LogLevel logLevel, const std::string &message);

  bool tryGet(char *buffer, size_t bufferSize);
  void get(char *buffer, size_t bufferSize);

private:
  static struct owner_t {
  } owner;
  static struct client_t {
  } client;

private:
  SHMLogger(owner_t, const std::string &instanceName);
  SHMLogger(client_t, const std::string &instanceName);

  // not implemented
  SHMLogger(const SHMLogger &reference);
  SHMLogger &operator=(const SHMLogger &reference);

  ~SHMLogger();

private:
  static SHMLogger *s_Instance;

  message_queue_interop m_LogQueue;

  std::string m_SHMName;
  std::string m_LockName;
  std::string m_QueueName;

  std::atomic<int> m_DroppedMessages;
};
