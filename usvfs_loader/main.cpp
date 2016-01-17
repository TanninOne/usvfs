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
#pragma warning(push,3)
#include <QApplication>
#include <QFileDialog>
#include <QCommandLineParser>
#include <QInputDialog>
#include <QDebug>
#include <QProgressDialog>
#pragma warning(pop)
#include <windows_sane.h>
#include <injectlib.h>
#include <shmlogger.h>
#include <scopeguard.h>
#include <fstream>
#include <Shlwapi.h>
#include <shellapi.h>
#include <directory_tree.h>
#include <usvfs.h>
#include <inject.h>
#include <stringutils.h>
#include <winapi.h>
#include <redirectiontree.h>
#include <spdlog.h>

namespace spd = spdlog;
using namespace InjectLib;
using namespace usvfs::shared;


void printLog(SHMLogger &logger)
{
  char buffer[1024];
  while (logger.tryGet(buffer, 1024)) {
    qDebug() << buffer;
  }
}

void gainPrivileges()
{
  HANDLE token;
  TOKEN_PRIVILEGES privileges;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid);
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
  }
}

int main(int argc, char *argv[])
{
  QApplication app(argc, argv);
  QApplication::setApplicationName("usvfs loader");
  QApplication::setApplicationVersion(PROJ_VERSION);

  QCommandLineParser parser;
  parser.setApplicationDescription("simple loader for usvfs");
  parser.addHelpOption();
  parser.addVersionOption();
  QCommandLineOption instanceNameOpt(QStringList() << "i" << "instance", "Set instance to run in", "name");
  parser.addOption(instanceNameOpt);
  parser.addOption(QCommandLineOption("pid", "ID of the process to attach to", "pid"));

  parser.process(app);

  std::shared_ptr<spd::logger> logger = spd::stdout_logger_mt("loader");

  if (parser.value(instanceNameOpt).length() == 0) {
    logger->warn("instance name has to be set");
    parser.showHelp(1);
  }

  try {
    SHMLogger &remoteLog = SHMLogger::create("usvfs");

    std::string shmName = parser.value(instanceNameOpt).toStdString();
    if (shmName.size() >= 65) {
      throw std::exception("instance name can't be longer than 64 characters");
    }
    if (!all_of(shmName.begin(), shmName.end(), isascii)) {
      throw std::exception("instance name must consist of only ascii characters");
    }

    USVFSParameters params;
    USVFSInitParameters(&params, shmName.c_str(), false, LogLevel::Debug);
    logger->info("initializing shm {}", shmName);
    ConnectVFS(&params);
    InitLogging(true);

    spdlog::drop("usvfs");
    spdlog::create<spdlog::sinks::stdout_sink_mt>("usvfs");

    QProgressDialog progress;
    progress.setMaximum(4);
    progress.setValue(0);
    for (auto link : { std::make_tuple(LR"(C:\temp\test.cpp)", LR"(C:\temp\test.txt)", false),
                       std::make_tuple(LR"(C:\temp\test.cpp)", LR"(C:\windows\test.txt)", false),
                       std::make_tuple(LR"(C:\temp\test.cpp)", LR"(C:\windows\Syswow64\test.txt)", false),
                       std::make_tuple(LR"(C:\QtSDK5)", LR"(C:\temp\QtSDK5)", true) }) {
      if (   (!std::get<2>(link)
              && !VirtualLinkFile(std::get<0>(link), std::get<1>(link), 0))
          || (std::get<2>(link)
              && !VirtualLinkDirectoryStatic(std::get<0>(link), std::get<1>(link), LINKFLAG_CREATETARGET))) {
        logger->critical("failed to create links: {}", GetLastError());
        printLog(remoteLog);
        return 1;
      }

      progress.setValue(progress.value() + 1);
      QCoreApplication::processEvents();
    }

    HANDLE processHandle = INVALID_HANDLE_VALUE;

    gainPrivileges();

    if (parser.value("pid").isEmpty()) {
      /*
      QString binaryName = QFileDialog::getOpenFileName();
      if (binaryName.isEmpty()) {
        return 0;
      }

      QString arguments = QInputDialog::getText(nullptr, QObject::tr("Commandline arguments"), QObject::tr("Arguments"));
      */

 /*     QString binaryName = R"(C:\Windows\notepad.exe)";
      QString arguments  = "";*/

      QString binaryName = R"(C:\Windows\explorer.exe)";
      QString arguments  = "/separate";

      {
        STARTUPINFO si;
        ::ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        PROCESS_INFORMATION pi;
        std::wstring commandLine = binaryName.toStdWString() + L" " + arguments.toStdWString();
        std::unique_ptr<wchar_t[]> cmdLineBuffer(new wchar_t[commandLine.size() + 1]);
        wcscpy_s(cmdLineBuffer.get(), commandLine.size() + 1, commandLine.c_str());
        BOOL res = CreateProcessHooked(nullptr, cmdLineBuffer.get()
                                       , nullptr, nullptr // no special process or thread attributes
                                       , FALSE            // don't inherit handles
                                       , 0                // no creation flags
                                       , nullptr          // same environment as parent
                                       , QFileInfo(binaryName).absolutePath().toStdWString().c_str()
                                       , &si, &pi);
        if (!res) {
          logger->critical("failed to start process");
          printLog(remoteLog);
          return 1;
        }
        processHandle = pi.hProcess;
      }
    } else {
      DWORD pid = parser.value("pid").toUInt();

      processHandle = OpenProcess(PROCESS_ALL_ACCESS
                                  , FALSE
                                  , pid);

      if (processHandle != nullptr) {
        usvfs::injectProcess(
            QCoreApplication::applicationDirPath().toStdWString(), params,
            processHandle, INVALID_HANDLE_VALUE);
      } else {
        logger->critical("failed to open handle for process {}: {}", pid, winapi::ex::ansi::errorString(::GetLastError()));
      }
    }

    std::ofstream output;
    output.open((qApp->applicationDirPath() + "/outlog.txt").toLocal8Bit().constData(), std::fstream::out);

    static const size_t MAX_COUNT = 5;
    size_t count = 1;
    DWORD waitPids[MAX_COUNT];
    waitPids[0] = ::GetProcessId(processHandle);

    char buffer[1024];
    while (count > 0) {
      logger->debug("waiting for:");
      for (DWORD pid : waitPids) {
        logger->debug("  pid: %lu", pid);
      }

      for (DWORD pid : waitPids) {
        HANDLE waitProc = OpenProcess(SYNCHRONIZE, FALSE, pid);

        DWORD res = 0UL;

        while ((res = WaitForSingleObject(waitProc, 100)) == WAIT_TIMEOUT) {
          while (remoteLog.tryGet(buffer, 1024)) {
            output << buffer << "\n";
          }
          output.flush();
        }
      }

      GetVFSProcessList(&count, waitPids);
    }
    while (remoteLog.tryGet(buffer, 1024)) {
      output << buffer << "\n";
    }
    output << "No more processes\n";
    output << "----- Ended -----\n";

    output.close();
    ::ShellExecute(nullptr, TEXT("open"),
                   (qApp->applicationDirPath() + "/outlog.txt").toStdWString().c_str(),
                   nullptr, nullptr, SW_SHOWNORMAL);
  } catch (const std::exception &e) {
    logger->critical("loader exception: {}", e.what());
  }

  return 0;
}
