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
#include "inject.h"
#include <winapi.h>
#include <exceptionex.h>
#include <loghelpers.h>
#include <spdlog.h>
#include <boost/filesystem.hpp>
#include <injectlib.h>
#include <stringutils.h>
#include <stringcast.h>
#include <string>
#include <utility>


namespace ush = usvfs::shared;

using namespace winapi;

void usvfs::injectProcess(const std::wstring &applicationPath
                          , const USVFSParameters &parameters
                          , const PROCESS_INFORMATION &processInfo)
{
  injectProcess(applicationPath, parameters, processInfo.hProcess, processInfo.hThread);
}

void usvfs::injectProcess(const std::wstring &applicationPath
                          , const USVFSParameters &parameters
                          , HANDLE processHandle
                          , HANDLE threadHandle)
{
  bool proc64 = false;
  bool sameBitness = false;
  {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    BOOL wow64;
    IsWow64Process(processHandle, &wow64);
    if (wow64) {
      // process is running under wow64 so it has to be a 32bit process running on 64bit windows
      proc64 = false;
      BOOL temp;
      IsWow64Process(GetCurrentProcess(), &temp);
      sameBitness = temp == TRUE;
    } else {
      BOOL selfWow64;
      IsWow64Process(GetCurrentProcess(), &selfWow64);
      if (selfWow64) {
        // WE are a 32 bit process running on 64bit windows. the other process isn't, so its 64bit
        proc64 = true;
      } else {
        sameBitness = true;
        // we have the same bitness as that other process, but which is it?
#ifdef _WIN64
        proc64 = true;
#else
        proc64 = false;
#endif
      }
    }
  }
  boost::filesystem::path binPath = boost::filesystem::path(applicationPath);
  spdlog::get("usvfs")->info("injecting to process {} with {} bitness",
                             ::GetProcessId(processHandle), sameBitness ? "same" : "different");

  if (sameBitness) {
    std::string libName = std::string("usvfs_") + (proc64 ? "x64" : "x86");
#ifdef _DEBUG
    std::wstring dllPath = (binPath / (libName + "-d.dll")).wstring();
#else // DEBUG
    std::wstring dllPath = (binPath / (libName + ".dll")).wstring();
#endif // DEBUG
    if (!boost::filesystem::exists(dllPath)) {
      USVFS_THROW_EXCEPTION(
          file_not_found_error()
          << ex_msg(std::string("dll missing: ")
                    + ush::string_cast<std::string>(dllPath).c_str()));
    }

    spdlog::get("usvfs")->debug("dll path: {}", log::wrap(dllPath));

    InjectLib::InjectDLL(processHandle, threadHandle, dllPath.c_str(),
                         "InitHooks", &parameters, sizeof(USVFSParameters));
  } else {
    std::wstring exePath = (binPath / "usvfs_proxy.exe").wstring();
    if (!boost::filesystem::exists(exePath)) {
      USVFS_THROW_EXCEPTION(file_not_found_error() << ex_msg(
                                std::string("exe missing: ")
                                + ush::string_cast<std::string>(exePath)));
    }
    // need to use proxy aplication to inject
    auto proxyProcess = std::move(wide::createProcess(exePath)
        .arg(L"--instance").arg(ush::string_cast<std::wstring>(parameters.instanceName))
        .arg(L"--pid").arg(GetProcessId(processHandle)));

    if (threadHandle != INVALID_HANDLE_VALUE) {
      proxyProcess.arg("--tid").arg(GetThreadId(threadHandle));
    }
    process::Result result = proxyProcess();
    if (!result.valid) {
      USVFS_THROW_EXCEPTION(unknown_error()
                            << ex_msg(std::string("failed to start proxy ")
                                      + ush::string_cast<std::string>(exePath))
                            << ex_win_errcode(result.errorCode));
    } else {
      // wait for proxy completion. this shouldn't take long, 5 seconds is very generous
      switch (WaitForSingleObject(result.processInfo.hProcess, 5000)) {
        case WAIT_TIMEOUT: {
            spdlog::get("usvfs")->debug("proxy timeout");
            TerminateProcess(result.processInfo.hProcess, 1);
            USVFS_THROW_EXCEPTION(timeout_error()
                                  << ex_msg(std::string("proxy didn't complete in time")));
          } break;
        case WAIT_FAILED: {
            spdlog::get("usvfs")->debug("proxy wait failed");
            TerminateProcess(result.processInfo.hProcess, 1);
            USVFS_THROW_EXCEPTION(unknown_error()
                                  << ex_msg(std::string("failed to wait for proxy completion"))
                                  << ex_win_errcode(result.errorCode));
          } break;
        default: {
            spdlog::get("usvfs")->debug("proxy run successful");
            // nop
          } break;
      }
    }
  }
}
