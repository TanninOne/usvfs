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

#include <inject.h>
#include <shared_memory.h>
#include <usvfsparameters.h>
#include <../usvfs_dll/hookcontext.h>
#include <shmlogger.h>
#include <spdlog.h>
#include <winapi.h>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>


namespace bi = boost::interprocess;
namespace bfs = boost::filesystem;
using usvfs::shared::SharedMemoryT;
using usvfs::SharedParameters;


template <typename T>
T getParameter(std::vector<std::string> &arguments, const std::string &key, bool consume)
{
  auto iter = std::find(arguments.begin(), arguments.end(), std::string("--") + key);
  if ((iter != arguments.end())
      && ((iter + 1) != arguments.end())) {
    T result = boost::lexical_cast<T>(*(iter + 1));
    if (consume) {
      arguments.erase(iter, iter + 2);
    }
    return result;
  } else {
    throw std::runtime_error(std::string("argument missing " + key));
  }
}

template <typename T>
T getParameter(std::vector<std::string> &arguments, const std::string &key, const T &def, bool consume)
{
  auto iter = std::find(arguments.begin(), arguments.end(), std::string("--") + key);
  if ((iter != arguments.end())
      && ((iter + 1) != arguments.end())) {
    T result = boost::lexical_cast<T>(*(iter + 1));
    if (consume) {
      arguments.erase(iter, iter + 2);
    }
    return result;
  } else {
    return def;
  }
}

int main(int argc, char **argv) {
  std::shared_ptr<spdlog::logger> logger;

  std::vector<std::string> arguments;
  std::copy(argv + 1, argv + argc, std::back_inserter(arguments));

  std::string instance;
  try {
    SHMLogger::open("usvfs");
    logger = spdlog::create<spdlog::sinks::shm_sink>("usvfs", "usvfs");
    logger->set_pattern("%H:%M:%S.%e [%L] (proxy) %v");

    instance = getParameter<std::string>(arguments, "instance", true);
  } catch (const std::exception &e) {
    if (logger.get() == nullptr) {
      return 1;
    }
    try {
      logger->critical("{}", e.what());
    } catch (const spdlog::spdlog_ex &) {
      // no way to log this
    } catch (const std::exception &) {
      logger->critical() << e.what();
    }
    return 1;
  }

  try {
    std::string executable =
        getParameter<std::string>(arguments, "executable", "", true);
    int pid = getParameter<int>(arguments, "pid", 0, true);
    int tid = getParameter<int>(arguments, "tid", 0, true);

    logger->info("instance: {}", instance);
    logger->info("exe: {}", executable);
    logger->info("pid: {}", pid);

    if (executable.empty() && (pid == 0)) {
      logger->warn("not all required settings set");
      return 1;
    }

    SharedMemoryT configurationSHM(bi::open_only, instance.c_str());
    if (!configurationSHM.check_sanity()) {
      logger->warn("failed to connect to vfs");
      return 1;
    }
    logger->info("size: {}", configurationSHM.get_size());
    logger->info("addr: {0:p}", configurationSHM.get_address());
    logger->info("objs: {}", configurationSHM.get_num_named_objects());
    std::pair<SharedParameters *, SharedMemoryT::size_type> params =
        configurationSHM.find<SharedParameters>("parameters");
    if (params.first == nullptr) {
      logger->error("failed to open shared configuration for {}", instance);
      return 1;
    }

    USVFSParameters par = params.first->makeLocal();

    boost::filesystem::path p(winapi::wide::getModuleFileName(nullptr));

    if (executable.empty()) {
      HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
      HANDLE threadHandle = INVALID_HANDLE_VALUE;
      if (tid != 0) {
        threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
      }
      usvfs::injectProcess(p.parent_path().wstring(), par, processHandle,
                           threadHandle);
    } else {
      winapi::process::Result process =
          winapi::ansi::createProcess(executable)
              .arguments(arguments.begin(), arguments.end())
              .workingDirectory(bfs::path(executable).parent_path().string())
              .suspended()();

      if (!process.valid) {
        return 1;
      }

      usvfs::injectProcess(p.parent_path().wstring(), par, process.processInfo);

      ResumeThread(process.processInfo.hThread);
    }

    return 0;
  } catch (const std::exception &e) {
    try {
      logger->critical("unhandled exception: {}", e.what());
      logExtInfo(e);
    } catch (const spdlog::spdlog_ex &) {
      // no way to log this
    } catch (const std::exception &) {
      logger->critical() << e.what();
    }
  }
}
