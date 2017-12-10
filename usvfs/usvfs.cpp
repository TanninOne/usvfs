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
#include "usvfs.h"
#include "hookmanager.h"
#include "redirectiontree.h"
#include "loghelpers.h"
#include <DbgHelp.h>
#include <ctime>
#include <shmlogger.h>
#include <winapi.h>
#include <boost/format.hpp>
#include <boost/tokenizer.hpp>
#include <boost/locale.hpp>
#include <boost/algorithm/string.hpp>
#include <ttrampolinepool.h>
#include <scopeguard.h>
#include <stringcast.h>
#include <inject.h>
#include <spdlog.h>
#pragma warning (push, 3)
#include <boost/filesystem.hpp>
#pragma warning (pop)
#include <fmt/format.h>
#include <codecvt>
#include <stdio.h>
#include <Psapi.h>


namespace bfs = boost::filesystem;
namespace ush = usvfs::shared;
namespace bip = boost::interprocess;
namespace ba  = boost::algorithm;

using usvfs::log::ConvertLogLevel;

usvfs::HookManager *manager = nullptr;
usvfs::HookContext *context = nullptr;
HMODULE dllModule = nullptr;
PVOID exceptionHandler = nullptr;
CrashDumpsType usvfs_dump_type = CrashDumpsType::None;
std::wstring usvfs_dump_path;

typedef std::codecvt_utf8_utf16<wchar_t> u8u16_convert;

static std::set<std::string> extensions { ".exe", ".dll" };

namespace spdlog {
  namespace sinks {
    class null_sink : public sink {

    public:
      null_sink() {}
      virtual void log(const details::log_msg&) override {}
      virtual void flush() override {}
    };
  }
}


//
// Logging
//

char *SeverityShort(LogLevel lvl)
{
  switch (lvl) {
    case LogLevel::Debug:   return "D";
    case LogLevel::Info:    return "I";
    case LogLevel::Warning: return "W";
    case LogLevel::Error:   return "E";
    default: return "?";
  }
}


void InitLoggingInternal(bool toConsole, bool connectExistingSHM)
{
  try {
    if (!toConsole && !SHMLogger::isInstantiated()) {
      if (connectExistingSHM) {
        SHMLogger::open("usvfs");
      } else {
        SHMLogger::create("usvfs");
      }
    }

    // a temporary logger was created in DllMain
    spdlog::drop("usvfs");
    #pragma message("need a customized name for the shm")
    auto logger = spdlog::get("usvfs");
    if (logger.get() == nullptr) {
      logger = toConsole ? spdlog::create<spdlog::sinks::stdout_sink_mt>("usvfs")
                         : spdlog::create<spdlog::sinks::shm_sink>("usvfs", "usvfs");
      logger->set_pattern("%H:%M:%S.%e [%L] %v");
    }
    logger->set_level(spdlog::level::debug);

    spdlog::drop("hooks");
    logger = spdlog::get("hooks");
    if (logger.get() == nullptr) {
      logger = toConsole ? spdlog::create<spdlog::sinks::stdout_sink_mt>("hooks")
                         : spdlog::create<spdlog::sinks::shm_sink>("hooks", "usvfs");
      logger->set_pattern("%H:%M:%S.%e <%P:%t> [%L] %v");
    }
    logger->set_level(spdlog::level::debug);
  } catch (const std::exception&) {
    // TODO should really report this
    //OutputDebugStringA((boost::format("init exception: %1%\n") % e.what()).str().c_str());
    if (spdlog::get("usvfs").get() == nullptr) {
      spdlog::create<spdlog::sinks::null_sink>("usvfs");
    }
    if (spdlog::get("hooks").get() == nullptr) {
      spdlog::create<spdlog::sinks::null_sink>("hooks");
    }
  }
}


void WINAPI InitLogging(bool toConsole)
{
  InitLoggingInternal(toConsole, false);
}

extern "C" DLLEXPORT bool WINAPI GetLogMessages(char *buffer, size_t size,
                                                bool blocking)
{
  buffer[0] = '\0';
  try {
    if (blocking) {
      SHMLogger::instance().get(buffer, size);
      return true;
    } else {
      return SHMLogger::instance().tryGet(buffer, size);
    }
  } catch (const std::exception &e) {
    _snprintf_s(buffer, size, _TRUNCATE, "Failed to retrieve log messages: %s",
               e.what());
    return false;
  }
}

void SetLogLevel(LogLevel level)
{
  spdlog::get("usvfs")->set_level(ConvertLogLevel(level));
  spdlog::get("hooks")->set_level(ConvertLogLevel(level));
}

extern "C" void WINAPI USVFSUpdateParams(LogLevel level, CrashDumpsType type)
{
  // update actual values used:
  usvfs_dump_type = type;
  SetLogLevel(level);
  // update parameters in context so spawned process will inherit changes:
  context->setLogLevel(level);
  context->setCrashDumpsType(type);
}

//
// Structured Exception handling
//

std::wstring generate_minidump_name(const wchar_t* dumpPath)
{
  DWORD pid = GetCurrentProcessId();
  wchar_t pname[100];
  if (GetModuleBaseName(GetCurrentProcess(), NULL, pname, _countof(pname)) == 0)
    return std::wstring();

  // find an available name:
  wchar_t dmpFile[MAX_PATH];
  int count = 0;
  _snwprintf_s(dmpFile, _TRUNCATE, L"%s\\%s-%lu.dmp", dumpPath, pname, pid);
  while (winapi::ex::wide::fileExists(dmpFile)) {
    if (++count > 99)
      return std::wstring();
    _snwprintf_s(dmpFile, _TRUNCATE, L"%s\\%s-%lu_%02d.dmp", dumpPath, pname, pid, count);
  }
  return dmpFile;
}

int createMiniDumpImpl(PEXCEPTION_POINTERS exceptionPtrs, CrashDumpsType type, const wchar_t* dumpPath, HMODULE dbgDLL)
{
  typedef BOOL (WINAPI *FuncMiniDumpWriteDump)(HANDLE process, DWORD pid, HANDLE file, MINIDUMP_TYPE dumpType,
                                               const PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
                                               const PMINIDUMP_USER_STREAM_INFORMATION userStreamParam,
                                               const PMINIDUMP_CALLBACK_INFORMATION callbackParam);

  // notice we avoid logging here on purpose because this is called from the VEHandler
  // and the logger can crash it in extreme cases.
  // additionally it is also called for MO crashes which use it's own logging.
  winapi::ex::wide::createPath(dumpPath);

  auto dmpName = generate_minidump_name(dumpPath);
  if (dmpName.empty())
    return 4;

  FuncMiniDumpWriteDump funcDump = reinterpret_cast<FuncMiniDumpWriteDump>(GetProcAddress(dbgDLL, "MiniDumpWriteDump"));
  if (!funcDump)
    return 5;

  HANDLE dumpFile = winapi::wide::createFile(dmpName).createAlways().access(GENERIC_WRITE).share(FILE_SHARE_WRITE)();
  if (dumpFile != INVALID_HANDLE_VALUE) {
    DWORD dumpType = MiniDumpNormal | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData;
    if (type == CrashDumpsType::Data)
      dumpType |= MiniDumpWithDataSegs;
    if (type == CrashDumpsType::Full)
      dumpType |= MiniDumpWithFullMemory;

    _MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
    exceptionInfo.ThreadId = GetCurrentThreadId();
    exceptionInfo.ExceptionPointers = exceptionPtrs;
    exceptionInfo.ClientPointers = FALSE;

    BOOL success =
      funcDump(GetCurrentProcess(), GetCurrentProcessId(), dumpFile, static_cast<MINIDUMP_TYPE>(dumpType), &exceptionInfo, nullptr, nullptr);

    CloseHandle(dumpFile);

    return success ? 0 : 7;
  }
  else
    return 6;
}

int WINAPI CreateMiniDump(PEXCEPTION_POINTERS exceptionPtrs, CrashDumpsType type, const wchar_t* dumpPath)
{
  if (type == CrashDumpsType::None)
    return 0;

  int res = 1;
  if (HMODULE dbgDLL = LoadLibraryW(L"dbghelp.dll"))
  {
    try {
      res = createMiniDumpImpl(exceptionPtrs, type, dumpPath, dbgDLL);
    }
    catch (...) {
      res = 2;
    }
    FreeLibrary(dbgDLL);
  }
  return res;
}

LONG WINAPI VEHandler(PEXCEPTION_POINTERS exceptionPtrs)
{
  // NOTICE: don't use logger in VEHandler as it can cause another fault causing VEHandler
  // to be called again and so on.

  if (   (exceptionPtrs->ExceptionRecord->ExceptionCode  < 0x80000000)      // non-critical
      || (exceptionPtrs->ExceptionRecord->ExceptionCode == 0xe06d7363)) {   // cpp exception
    // don't report non-critical exceptions
    return EXCEPTION_CONTINUE_SEARCH;
  }
  /*
  if (((exceptionPtrs->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) ||
      (exceptionPtrs->ExceptionRecord->ExceptionCode == 0xe06d7363)) {
    // don't want to break on non-critical exceptions. 0xe06d7363 indicates a C++ exception. why are those marked non-continuable?
    return EXCEPTION_CONTINUE_SEARCH;
  }
  */

  // disable our hooking mechanism to increase chances the dump writing won't crash
  HookLib::TrampolinePool::instance().forceUnlockBarrier();
  HookLib::TrampolinePool::instance().setBlock(true);

  CreateMiniDump(exceptionPtrs, usvfs_dump_type, usvfs_dump_path.c_str());

  return EXCEPTION_CONTINUE_SEARCH;
}

//
// Exported functions
//

void __cdecl InitHooks(LPVOID parameters, size_t)
{
  InitLoggingInternal(false, true);

  const USVFSParameters *params = reinterpret_cast<USVFSParameters *>(parameters);
  usvfs_dump_type = params->crashDumpsType;
  usvfs_dump_path = ush::string_cast<std::wstring>(params->crashDumpsPath, ush::CodePage::UTF8);

  SetLogLevel(params->logLevel);

  if (exceptionHandler == nullptr) {
    if (usvfs_dump_type != CrashDumpsType::None)
      exceptionHandler = ::AddVectoredExceptionHandler(0, VEHandler);
  } else {
    spdlog::get("usvfs")->info("vectored exception handler already active");
    // how did this happen??
  }

  spdlog::get("usvfs")
      ->info("inithooks called {0} in process {1}:{2} (log level {3}, dump type {4}, dump path {5})",
              params->instanceName,
              winapi::ansi::getModuleFileName(nullptr),
              ::GetCurrentProcessId(),
              static_cast<int>(params->logLevel),
              static_cast<int>(params->crashDumpsType),
              params->crashDumpsPath);

  try {
    manager = new usvfs::HookManager(*params, dllModule);

    spdlog::get("usvfs")
      ->info("inithooks in process {0} successfull", ::GetCurrentProcessId());

/*
    std::ostringstream str;
    dumpTree(str, *manager->context()->redirectionTable().get());
    typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
    boost::char_separator<char> sep("\n");
    tokenizer tok(str.str(), sep);
    for (auto && s : tok)
      spdlog::get("usvfs")->debug("{}", s);
*/
    //context = manager->context();
  } catch (const std::exception &e) {
    spdlog::get("usvfs")->debug("failed to initialise hooks: {0}", e.what());
  }
}


void WINAPI GetCurrentVFSName(char *buffer, size_t size)
{
  ush::strncpy_sz(buffer, context->callParameters().currentSHMName, size);
}


BOOL WINAPI CreateVFS(const USVFSParameters *params)
{
  usvfs::HookContext::remove(params->instanceName);
  return ConnectVFS(params);
}

BOOL WINAPI ConnectVFS(const USVFSParameters *params)
{
  if (spdlog::get("usvfs").get() == nullptr) {
    // create temporary logger so we don't get null-pointer exceptions
    spdlog::create<spdlog::sinks::null_sink>("usvfs");
  }

  try {
    DisconnectVFS();
    context = new usvfs::HookContext(*params, dllModule);

    return TRUE;
  } catch (const std::exception &e) {
    spdlog::get("usvfs")->debug("failed to connect to vfs: {}", e.what());
    return FALSE;
  }
}


void WINAPI DisconnectVFS()
{
  if (spdlog::get("usvfs").get() == nullptr) {
    // create temporary logger so we don't get null-pointer exceptions
    spdlog::create<spdlog::sinks::null_sink>("usvfs");
  }

  spdlog::get("usvfs")->debug("remove from process {}", GetCurrentProcessId());
  if (manager != nullptr) {
    spdlog::get("usvfs")->debug("manager not null");
    delete manager;
    manager = nullptr;
  }
  if (context != nullptr) {
    spdlog::get("usvfs")->debug("context not null");
    delete context;
    context = nullptr;
    spdlog::get("usvfs")->debug("vfs unloaded");
  }
}


bool processStillActive(DWORD pid)
{
  HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

  if (proc == nullptr) {
    return false;
  }

  ON_BLOCK_EXIT([&]() {
	  if (proc != INVALID_HANDLE_VALUE)
		  ::CloseHandle(proc);
  });

  DWORD exitCode;
  if (!GetExitCodeProcess(proc, &exitCode)) {
    spdlog::get("usvfs")->warn("failed to query exit code on process {}: {}",
                               pid, ::GetLastError());
    return false;
  } else {
    return exitCode == STILL_ACTIVE;
  }
}


BOOL WINAPI GetVFSProcessList(size_t *count, LPDWORD processIDs)
{
  if (count == nullptr) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  if (context == nullptr) {
    *count = 0;
  } else {
    std::vector<DWORD> pids = context->registeredProcesses();
    size_t realCount = 0;
    for (DWORD pid : pids) {
      if (processStillActive(pid)) {
        if ((realCount < *count) && (processIDs != nullptr)) {
          processIDs[realCount] = pid;
        }

        ++realCount;
      } // else the process has already ended
    }
    *count = realCount;
  }
  return TRUE;
}

void WINAPI ClearVirtualMappings()
{
  context->redirectionTable()->clear();
  context->inverseTable()->clear();
}

/// ensure the specified path exists. If a physical path of the same name
/// exists, it is inserted into the virtual directory as an empty reference. If
/// the path doesn't exist virtually and can't be cloned from a physical
/// directory, this returns false
/// \todo if this fails (i.e. not all intermediate directories exists) any
/// intermediate directories already created aren't removed
bool assertPathExists(usvfs::RedirectionTreeContainer &table, LPCWSTR path)
{
  bfs::path p(path);
  p = p.parent_path();

  usvfs::RedirectionTree::NodeT *current = table.get();

  for (auto iter = p.begin(); iter != p.end();
       iter = ush::nextIter(iter, p.end())) {
    if (current->exists(iter->string().c_str())) {
      // subdirectory exists virtually, all good
      usvfs::RedirectionTree::NodePtrT found
          = current->node(iter->string().c_str());
      current = found.get().get();
    } else {
      // targetPath is relative to the last rerouted "real" path. This means
      // that if virtual c:/foo maps to real c:/windows then creating virtual
      // c:/foo/bar will map to real c:/windows/bar
      bfs::path targetPath
          = current->data().linkTarget.size() > 0
                ? bfs::path(current->data().linkTarget.c_str()) / *iter
                : *iter / "\\";
      if (is_directory(targetPath)) {
        usvfs::RedirectionTree::NodePtrT newNode = table.addDirectory(
            current->path() / *iter, targetPath.string().c_str(),
            ush::FLAG_DUMMY, false);
        current = newNode.get().get();
      } else {
        spdlog::get("usvfs")->info("{} doesn't exist", targetPath);
        return false;
      }
    }
  }

  return true;
}

BOOL WINAPI VirtualLinkFile(LPCWSTR source, LPCWSTR destination,
                            unsigned int flags)
{
  // TODO difference between winapi and ntdll api regarding system32 vs syswow64
  // (and other windows links?)
  try {
    if (!assertPathExists(context->redirectionTable(), destination)) {
      SetLastError(ERROR_PATH_NOT_FOUND);
      return FALSE;
    }

    std::string sourceU8
        = ush::string_cast<std::string>(source, ush::CodePage::UTF8);
    auto res = context->redirectionTable().addFile(
        bfs::path(destination), usvfs::RedirectionDataLocal(sourceU8),
        !(flags & LINKFLAG_FAILIFEXISTS));

    std::string fileExt = ba::to_lower_copy(bfs::extension(sourceU8));
    if (extensions.find(fileExt) != extensions.end()) {
      std::string destinationU8
          = ush::string_cast<std::string>(destination, ush::CodePage::UTF8);

      context->inverseTable().addFile(
          bfs::path(source), usvfs::RedirectionDataLocal(destinationU8), true);
    }

    context->updateParameters();

    if (res.get() == nullptr) {
      // the tree structure currently doesn't provide useful error codes but
      // this is currently the only reason
      // we would return a nullptr.
      SetLastError(ERROR_FILE_EXISTS);
      return FALSE;
    } else {
      return TRUE;
    }
  } catch (const std::exception &e) {
    spdlog::get("usvfs")->error("failed to copy file {}", e.what());
    // TODO: no clue what's wrong
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}

/**
 * @brief extract the flags relevant to redirection
 */
static usvfs::shared::TreeFlags convertRedirectionFlags(unsigned int flags)
{
  usvfs::shared::TreeFlags result = 0;
  if (flags & LINKFLAG_CREATETARGET) {
    result |= usvfs::shared::FLAG_CREATETARGET;
  }
  return result;
}


BOOL WINAPI VirtualLinkDirectoryStatic(LPCWSTR source, LPCWSTR destination, unsigned int flags)
{
  // TODO change notification not yet implemented
  try {
    if ((flags & LINKFLAG_FAILIFEXISTS)
        && winapi::ex::wide::fileExists(destination)) {
      SetLastError(ERROR_FILE_EXISTS);
      return FALSE;
    }

    if (!assertPathExists(context->redirectionTable(), destination)) {
      SetLastError(ERROR_PATH_NOT_FOUND);
      return FALSE;
    }

    std::string sourceU8
        = ush::string_cast<std::string>(source, ush::CodePage::UTF8) + "\\";

    context->redirectionTable().addDirectory(
          destination, usvfs::RedirectionDataLocal(sourceU8),
          usvfs::shared::FLAG_DIRECTORY | convertRedirectionFlags(flags),
          (flags & LINKFLAG_CREATETARGET) != 0);

    if ((flags & LINKFLAG_RECURSIVE) != 0) {
      std::wstring sourceP(source);
      std::wstring sourceW      = sourceP + L"\\";
      std::wstring destinationW = std::wstring(destination) + L"\\";
      if (sourceP.length() >= MAX_PATH && !ush::startswith(sourceP.c_str(), LR"(\\?\)"))
        sourceP = LR"(\\?\)" + sourceP;

      for (winapi::ex::wide::FileResult file :
           winapi::ex::wide::quickFindFiles(sourceP.c_str(), L"*")) {
        if (file.attributes & FILE_ATTRIBUTE_DIRECTORY) {
          if ((file.fileName != L".") && (file.fileName != L"..")) {
            VirtualLinkDirectoryStatic((sourceW + file.fileName).c_str(),
                                       (destinationW + file.fileName).c_str(),
                                       flags);
          }
        } else {
          std::string nameU8 = ush::string_cast<std::string>(
              file.fileName.c_str(), ush::CodePage::UTF8);

          // TODO could save memory here by storing only the file name for the
          // source and constructing the full name using the parent directory
          context->redirectionTable().addFile(
              bfs::path(destination) / nameU8,
              usvfs::RedirectionDataLocal(sourceU8 + nameU8), true);

          std::string fileExt = ba::to_lower_copy(bfs::extension(nameU8));

          if (extensions.find(fileExt) != extensions.end()) {
            std::string destinationU8 = ush::string_cast<std::string>(
                                            destination, ush::CodePage::UTF8)
                                        + "\\";

            context->inverseTable().addFile(
                bfs::path(source) / nameU8,
                usvfs::RedirectionDataLocal(destinationU8 + nameU8), true);
          }
        }
      }
    }

    context->updateParameters();

    return TRUE;
  } catch (const std::exception &e) {
    spdlog::get("usvfs")->error("failed to copy file {}", e.what());
    // TODO: no clue what's wrong
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}


BOOL WINAPI CreateProcessHooked(LPCWSTR lpApplicationName
                                , LPWSTR lpCommandLine
                                , LPSECURITY_ATTRIBUTES lpProcessAttributes
                                , LPSECURITY_ATTRIBUTES lpThreadAttributes
                                , BOOL bInheritHandles
                                , DWORD dwCreationFlags
                                , LPVOID lpEnvironment
                                , LPCWSTR lpCurrentDirectory
                                , LPSTARTUPINFOW lpStartupInfo
                                , LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  DWORD flags = dwCreationFlags | CREATE_SUSPENDED;

  BOOL res = CreateProcessW(lpApplicationName, lpCommandLine
                            , lpProcessAttributes, lpThreadAttributes
                            , bInheritHandles, flags
                            , lpEnvironment, lpCurrentDirectory
                            , lpStartupInfo, lpProcessInformation);
  if (!res) {
    spdlog::get("usvfs")->error("failed to spawn {}", ush::string_cast<std::string>(lpCommandLine));
    return FALSE;
  }

  std::wstring applicationDirPath = winapi::wide::getModuleFileName(dllModule);
  boost::filesystem::path p(applicationDirPath);
  try {
    usvfs::injectProcess(p.parent_path().wstring(), context->callParameters(),
                         *lpProcessInformation);
  } catch (const std::exception &e) {
    spdlog::get("usvfs")->error("failed to inject: {}", e.what());
    logExtInfo(e, LogLevel::Error);
    ::TerminateProcess(lpProcessInformation->hProcess, 1);
    ::SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  if (!susp) {
    ResumeThread(lpProcessInformation->hThread);
  }

  return TRUE;
}


BOOL WINAPI CreateVFSDump(LPSTR buffer, size_t *size)
{
  assert(size != nullptr);
  std::ostringstream output;
  usvfs::shared::dumpTree(output, *context->redirectionTable().get());
  std::string str = output.str();
  if ((buffer != NULL) && (*size > 0)) {
    strncpy_s(buffer, *size, str.c_str(), _TRUNCATE);
  }
  bool success = *size >= str.length();
  *size = str.length();
  return success ? TRUE : FALSE;
}


VOID WINAPI BlacklistExecutable(LPWSTR executableName)
{
  context->blacklistExecutable(executableName);
}


VOID WINAPI PrintDebugInfo()
{
  spdlog::get("usvfs")
      ->warn("===== debug {} =====", context->redirectionTable().shmName());
  void *buffer = nullptr;
  size_t bufferSize = 0;
  context->redirectionTable().getBuffer(buffer, bufferSize);
  std::ostringstream temp;
  for (size_t i = 0; i < bufferSize; ++i) {
    temp << std::hex << std::setfill('0') << std::setw(2) << (unsigned)reinterpret_cast<char*>(buffer)[i] << " ";
    if ((i % 16) == 15) {
      spdlog::get("usvfs")->info("{}", temp.str());
      temp.str("");
      temp.clear();
    }
  }
  if (!temp.str().empty()) {
    spdlog::get("usvfs")->info("{}", temp.str());
  }
  spdlog::get("usvfs")
      ->warn("===== / debug {} =====", context->redirectionTable().shmName());
}


void WINAPI USVFSInitParameters(USVFSParameters *parameters,
                                const char *instanceName, bool debugMode,
                                LogLevel logLevel,
                                CrashDumpsType crashDumpsType,
                                const char *crashDumpsPath)
{
  parameters->debugMode = debugMode;
  parameters->logLevel = logLevel;
  parameters->crashDumpsType = crashDumpsType;
  strncpy_s(parameters->instanceName, instanceName, _TRUNCATE);
  if (crashDumpsPath && *crashDumpsPath && strlen(crashDumpsPath) < _countof(parameters->crashDumpsPath)) {
    memcpy(parameters->crashDumpsPath, crashDumpsPath, strlen(crashDumpsPath)+1);
    parameters->crashDumpsType = crashDumpsType;
  }
  else {
    // crashDumpsPath invalid or overflow of USVFSParameters variable so disable crash dumps:
    parameters->crashDumpsPath[0] = 0;
    parameters->crashDumpsType = CrashDumpsType::None;
  }
  // we can't use the whole buffer as we need a few bytes to store a running
  // counter
  strncpy_s(parameters->currentSHMName, 60, instanceName, _TRUNCATE);
  memset(parameters->currentInverseSHMName, '\0', _countof(parameters->currentInverseSHMName));
  _snprintf(parameters->currentInverseSHMName, 60, "inv_%s", instanceName);
}


//
// DllMain
//

BOOL APIENTRY DllMain(HMODULE module,
                      DWORD  reasonForCall,
                      LPVOID)
{
  switch (reasonForCall) {
    case DLL_PROCESS_ATTACH: {
      dllModule = module;
    } break;
    case DLL_PROCESS_DETACH: {
      if (exceptionHandler)
        ::RemoveVectoredExceptionHandler(exceptionHandler);
    } break;
    case DLL_THREAD_ATTACH: {
    } break;
    case DLL_THREAD_DETACH: {
    } break;
  }

  return TRUE;
}
