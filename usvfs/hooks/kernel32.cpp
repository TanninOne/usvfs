#include "kernel32.h"
#include "sharedids.h"
#include "../loghelpers.h"
#include "../hookmanager.h"
#include "../hookcontext.h"
#include "../hookcallcontext.h"
#include <inject.h>
#include <winapi.h>
#include <shellapi.h>
#include <stringutils.h>
#include <stringcast.h>
#include <set>
#include <boost/filesystem.hpp>

#include <sstream>


namespace ush = usvfs::shared;
namespace bfs = boost::filesystem;
using ush::string_cast;
using ush::CodePage;


class RerouteW {
  std::wstring m_Buffer{};
  std::wstring m_RealPath{};
  bool m_Rerouted{ false };
  LPCWSTR m_FileName{ nullptr };
private:
  RerouteW() = default;
public:
  RerouteW(RerouteW &&reference)
    : m_Buffer(reference.m_Buffer)
    , m_RealPath(reference.m_RealPath)
    , m_Rerouted(reference.m_Rerouted)
  {
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
  }
  RerouteW &operator=(RerouteW &&reference) {
    m_Buffer = reference.m_Buffer;
    m_RealPath = reference.m_RealPath;
    m_Rerouted = reference.m_Rerouted;
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
    return *this;
  }

  RerouteW(const RerouteW &reference) = delete;
  RerouteW &operator=(const RerouteW&) = delete;

  LPCWSTR fileName() const { return m_FileName; }
  bool wasRerouted() const { return m_Rerouted; }

  void insertMapping(const usvfs::HookContext::Ptr &context) {
    context->redirectionTable().addFile(
          m_RealPath
          , usvfs::RedirectionDataLocal(string_cast<std::string>(m_FileName)));
  }

  static RerouteW create(const usvfs::HookContext::ConstPtr &context
                        , const usvfs::HookCallContext &callContext
                        , const wchar_t *inPath)
  {
    RerouteW result;
    if ((inPath != nullptr)
        && (inPath[0] != L'\0')
        && !ush::startswith(inPath, L"hid#")) {
      result.m_Buffer   = std::wstring(inPath);
      result.m_Rerouted = false;

      if (callContext.active()) {
        bool absolute = false;
        if (ush::startswith(inPath, LR"(\\?\)")) {
          absolute = true;
          inPath += 4;
        } else if (inPath[1] == L':') {
          absolute = true;
        }

        std::string lookupPath;
        if (!absolute) {
          usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FULL_PATHNAME);
          auto fullPath = winapi::wide::getFullPathName(inPath);
          lookupPath
              = string_cast<std::string>(fullPath.first, CodePage::UTF8);
        } else {
          lookupPath = string_cast<std::string>(inPath, CodePage::UTF8);
        }

        auto node = context->redirectionTable()->findNode(lookupPath.c_str());

        if ((node.get() != nullptr) && !node->data().linkTarget.empty()) {
          result.m_Buffer = string_cast<std::wstring>(
              node->data().linkTarget.c_str(), CodePage::UTF8);
          result.m_Rerouted = true;
        }
      }
/*      if (*result.m_Buffer.rbegin() == L'\\') {
        result.m_Buffer.resize(result.m_Buffer.length() - 1);
      }
      */
      result.m_FileName = result.m_Buffer.c_str();
    }
    return result;
  }

  static RerouteW createNew(const usvfs::HookContext::ConstPtr &context
                            , const usvfs::HookCallContext &callContext
                            , LPCWSTR inPath)
  {
    UNUSED_VAR(callContext);
    RerouteW result;
    result.m_RealPath.assign(inPath);
    result.m_Buffer = inPath;
    result.m_Rerouted = false;

    if ((inPath != nullptr)
        && (inPath[0] != L'\0')
        && !ush::startswith(inPath, L"hid#")) {
      bool absolute = false;
      if (ush::startswith(inPath, LR"(\\?\)")) {
        absolute = true;
        inPath += 4;
      } else if (inPath[1] == L':') {
        absolute = true;
      }

      std::string lookupPath;
      if (!absolute) {
        usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FULL_PATHNAME);
        auto fullPath = winapi::wide::getFullPathName(inPath);
        lookupPath = string_cast<std::string>(fullPath.first, CodePage::UTF8);
      } else {
        lookupPath = string_cast<std::string>(inPath, CodePage::UTF8);
      }

      FindCreateTarget visitor;
      usvfs::RedirectionTree::VisitorFunction visitorWrapper =
          [&] (const usvfs::RedirectionTree::NodePtrT &node) { visitor(node); };
      context->redirectionTable()->visitPath(lookupPath, visitorWrapper);
      if (visitor.target.get() != nullptr) {
        // the visitor has found the last (deepest in the directory hierarchy)
        // create-target
        bfs::path relativePath = ush::make_relative(visitor.target->path()
                                                    , bfs::path(lookupPath));
        result.m_Buffer = (bfs::path(visitor.target->data().linkTarget.c_str())
                           / relativePath).wstring();

        result.m_Rerouted = true;
      }
    }

    result.m_FileName = result.m_Buffer.c_str();

    return result;
  }

private:

  struct FindCreateTarget {
    usvfs::RedirectionTree::NodePtrT target;
    void operator()(usvfs::RedirectionTree::NodePtrT node) {
      if (node->hasFlag(usvfs::shared::FLAG_CREATETARGET)) {
        target = node;
      }
    }
  };
};


HMODULE WINAPI usvfs::hooks::LoadLibraryW(LPCWSTR lpFileName)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::LOAD_LIBRARY)

  PRE_REALCALL
  res = ::LoadLibraryW(lpFileName);
  POST_REALCALL

  if (false) {
    LOG_CALL().PARAMWRAP(lpFileName).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::LoadLibraryA(LPCSTR lpFileName)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::LOAD_LIBRARY)

  PRE_REALCALL
  res = ::LoadLibraryA(lpFileName);
  POST_REALCALL

  if (false) {
    LOG_CALL().PARAM(lpFileName).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::LoadLibraryExW(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::LOAD_LIBRARY)

  PRE_REALCALL
  res = ::LoadLibraryExW(lpFileName, hFile, dwFlags);
  POST_REALCALL

  if (false) {
    LOG_CALL().PARAM(lpFileName).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::LoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::LOAD_LIBRARY)

  PRE_REALCALL
  res = ::LoadLibraryExA(lpFileName, hFile, dwFlags);
  POST_REALCALL

  if (false) {
    LOG_CALL().PARAM(lpFileName).PARAM(res);
  }

  HOOK_END

  return res;
}

/// determine name of the binary to run based on parameters for createprocess
std::wstring getBinaryName(LPCWSTR applicationName, LPCWSTR lpCommandLine)
{
  if (applicationName != nullptr) {
    std::pair<std::wstring, std::wstring> fullPath = winapi::wide::getFullPathName(applicationName);
    return fullPath.second;
  } else {
    if (lpCommandLine[0] == '"') {
      const wchar_t *endQuote = wcschr(lpCommandLine, '"');
      if (endQuote != nullptr) {
        return std::wstring(lpCommandLine + 1, endQuote - 1);
      }
    }

    // according to the documentation, if the commandline is unquoted and has
    // spaces, it will be interpreted in multiple ways, i.e.
    // c:\program.exe files\sub dir\program name
    // c:\program files\sub.exe dir\program name
    // c:\program files\sub dir\program.exe name
    // c:\program files\sub dir\program name.exe
    LPCWSTR space = wcschr(lpCommandLine, L' ');
    while (space != nullptr) {
      std::wstring subString(lpCommandLine, space);
      bool isDirectory = true;
      if (winapi::ex::wide::fileExists(subString.c_str(), &isDirectory)
          && !isDirectory) {
        return subString;
      } else {
        space = wcschr(space + 1, L' ');
      }
    }
    return std::wstring(lpCommandLine);
  }
}


BOOL WINAPI usvfs::hooks::CreateProcessA(LPCSTR lpApplicationName
                                         , LPSTR lpCommandLine
                                         , LPSECURITY_ATTRIBUTES lpProcessAttributes
                                         , LPSECURITY_ATTRIBUTES lpThreadAttributes
                                         , BOOL bInheritHandles
                                         , DWORD dwCreationFlags
                                         , LPVOID lpEnvironment
                                         , LPCSTR lpCurrentDirectory
                                         , LPSTARTUPINFOA lpStartupInfo
                                         , LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)
  if (!callContext.active()) {
    return ::CreateProcessA(
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  }

  HookContext::ConstPtr context = HookContext::readAccess();

  // remember if the caller wanted the process to be suspended. If so, we don't resume when
  // we're done
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  dwCreationFlags |= CREATE_SUSPENDED;

  RerouteW applicationReroute = RerouteW::create(
      context, callContext,
      lpApplicationName != nullptr
          ? ush::string_cast<std::wstring>(lpApplicationName).c_str()
          : nullptr);
  RerouteW cwdReroute = RerouteW::create(
      context, callContext,
      lpCurrentDirectory != nullptr
          ? ush::string_cast<std::wstring>(lpCurrentDirectory).c_str()
          : nullptr);

  // TODO apply rerouting on command line

  PRE_REALCALL
  res = ::CreateProcessA(
      ush::string_cast<std::string>(applicationReroute.fileName()).c_str(),
      lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
      dwCreationFlags, lpEnvironment,
      lpCurrentDirectory != nullptr
          ? ush::string_cast<std::string>(cwdReroute.fileName()).c_str()
          : nullptr,
      lpStartupInfo, lpProcessInformation);
  POST_REALCALL

  // hook unless blacklisted
  // TODO implement process blacklisting. Currently disabled because storing in redirection-tree doesn't work and makes no sense
//  std::wstring binaryName = getBinaryName(applicationReroute.fileName(), lpCommandLine);
//  bool blacklisted = context->redirectionTable()->testProcessBlacklisted(usvfs::shared::toNarrow(binaryName.c_str()).c_str());
  bool blacklisted = false;
  if (!blacklisted) {
    try {
      injectProcess(context->dllPath()
                    , context->callParameters()
                    , *lpProcessInformation);
    } catch (const std::exception &e) {
      spdlog::get("hooks")->error("failed to inject into {0}: {1}",
        log::wrap(applicationReroute.fileName()), e.what());
    }
  }

  // resume unless process is suposed to start suspended
  if (!susp && (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    spdlog::get("hooks")->error("failed to inject into spawned process");
    res = FALSE;
  }

  LOG_CALL().PARAM(applicationReroute.fileName())
            .PARAM(lpCommandLine)
            .PARAM(blacklisted)
            .PARAM(res);

  HOOK_END

  return res;
}


BOOL WINAPI usvfs::hooks::CreateProcessW(LPCWSTR lpApplicationName
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
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)
  if (!callContext.active()) {
    return ::CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                            lpThreadAttributes, bInheritHandles, dwCreationFlags,
                            lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  }

  HookContext::ConstPtr context = HookContext::readAccess();

  // remember if the caller wanted the process to be suspended. If so, we don't resume when
  // we're done
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  dwCreationFlags |= CREATE_SUSPENDED;

  std::wstring cmdline;
  if (lpCommandLine != nullptr) {
    // decompose command line
    int argc = 0;
    LPWSTR *argv = ::CommandLineToArgvW(lpCommandLine, &argc);
    ON_BLOCK_EXIT([argv] () { LocalFree(argv); });

    RerouteW cmdReroute = RerouteW::create(context, callContext, argv[0]);

    // recompose command line
    std::wstringstream stream;
    stream << "\"" << cmdReroute.fileName() << "\"";
    for (int i = 1; i < argc; ++i) {
      stream << " " << argv[i];
    }
    cmdline = stream.str();
  }

  RerouteW applicationReroute = RerouteW::create(context, callContext, lpApplicationName);

  PRE_REALCALL
  res = ::CreateProcessW(applicationReroute.fileName(),
                         lpCommandLine != nullptr ? &cmdline[0] : nullptr,
                         lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags,
                         lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation);
  POST_REALCALL

  // hook unless blacklisted
  // TODO implement process blacklisting. Currently disabled because storing in redirection-tree doesn't work and makes no sense
//  std::wstring binaryName = getBinaryName(applicationReroute.fileName(), lpCommandLine);
//  bool blacklisted = context->redirectionTable()->testProcessBlacklisted(usvfs::shared::toNarrow(binaryName.c_str()).c_str());
  bool blacklisted = false;
  if (!blacklisted) {
    try {
      injectProcess(context->dllPath()
                           , context->callParameters()
                           , *lpProcessInformation);
    } catch (const std::exception &e) {
      spdlog::get("hooks")->error("failed to inject into {0}: {1}"
                                  , lpApplicationName != nullptr ? log::wrap(applicationReroute.fileName())
                                                                 : log::wrap(static_cast<LPCWSTR>(lpCommandLine))
                                  , e.what());
    }
  }

  // resume unless process is suposed to start suspended
  if (!susp && (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    spdlog::get("hooks")->error("failed to inject into spawned process");
    res = FALSE;
  }

  LOG_CALL().PARAM(applicationReroute.fileName())
            .PARAM(cmdline)
            .PARAM(blacklisted)
            .PARAM(res);

  HOOK_END

  return res;
}

bool fileExists(LPCWSTR fileName)
{
  DWORD attrib = GetFileAttributesW(fileName);
  return ((attrib != INVALID_FILE_ATTRIBUTES)
          && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

DWORD fileAttributesRegular(LPCWSTR fileName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  return GetFileAttributesW(fileName);
}

DWORD fileAttributesRegular(LPCSTR fileName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  return GetFileAttributesW(ush::string_cast<std::wstring>(fileName).c_str());
}

HANDLE WINAPI usvfs::hooks::CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  bool storePath = false;
  if ((dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS) != 0UL) {
    // this may be an attempt to open a directory handle for iterating.
    // If so we need to treat it a little bit differently
    bool isDir = false;
    bool exists = false;
    { // first check in the original location!
      DWORD attributes = fileAttributesRegular(lpFileName);
      exists = attributes != INVALID_FILE_ATTRIBUTES;
      if (exists) {
        isDir = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL;
      }
    }
    if (!exists) {
      // if the file/directory doesn't exist in the original location,
      // we need to check in rerouted locations as well
      DWORD attributes = GetFileAttributesW(lpFileName);
      isDir = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL;
    }

    if (isDir) {
      if (exists) {
        // if its a directory and it exists in the original location, open that
        return ::CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                             lpSecurityAttributes, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
      } else {
        // if its a directory and it only exists "virtually" then we need to
        // store the path for when the caller iterates the directory
        storePath = true;
      }
    }
  }

  RerouteW reroute
      = RerouteW::create(HookContext::readAccess(), callContext, lpFileName);

  bool create = false;

  if (((dwCreationDisposition == CREATE_ALWAYS)
       || (dwCreationDisposition == CREATE_NEW))
      && !reroute.wasRerouted() && !fileExists(lpFileName)) {
    // the file will be created so now we need to know where
    reroute = RerouteW::createNew(HookContext::readAccess(), callContext,
                                  lpFileName);
    create = reroute.wasRerouted();
  }

  PRE_REALCALL
  res = ::CreateFileW(reroute.fileName(), dwDesiredAccess, dwShareMode,
                      lpSecurityAttributes, dwCreationDisposition,
                      dwFlagsAndAttributes, hTemplateFile);
  POST_REALCALL

  if (create && (res != INVALID_HANDLE_VALUE)) {
    // new file was created in a mapped directory, insert to vitual structure
    reroute.insertMapping(HookContext::writeAccess());
  }

  if ((res != INVALID_HANDLE_VALUE) && storePath) {
    // store the original search path for use during iteration
    HookContext::ConstPtr context = HookContext::readAccess();
    context->customData<SearchHandleMap>(SearchHandles)[res] = lpFileName;
#pragma message("need to clean up this handle in CloseHandle call")
  }

  if (reroute.wasRerouted()) {
    LOG_CALL()
        .PARAM(lpFileName)
        .PARAM(reroute.fileName())
        .PARAMHEX(dwDesiredAccess)
        .PARAMHEX(dwCreationDisposition)
        .PARAMHEX(dwFlagsAndAttributes)
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
  }
  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::GetFileAttributesExW(
    LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute
      = RerouteW::create(HookContext::readAccess(), callContext, lpFileName);
  PRE_REALCALL
  res = ::GetFileAttributesExW(reroute.fileName(), fInfoLevelId,
                               lpFileInformation);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetFileAttributesW(LPCWSTR lpFileName)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute = RerouteW::create(HookContext::readAccess(), callContext, lpFileName);
  PRE_REALCALL
  res = ::GetFileAttributesW(reroute.fileName());
  POST_REALCALL

  if (true || reroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
        ;
  }

  HOOK_ENDP(usvfs::log::wrap(lpFileName));

  return res;
}

DWORD WINAPI usvfs::hooks::SetFileAttributesW(LPCTSTR lpFileName
                                              , DWORD dwFileAttributes)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute = RerouteW::create(HookContext::readAccess(), callContext, lpFileName);
  PRE_REALCALL
  res = ::SetFileAttributesW(reroute.fileName(), dwFileAttributes);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAMWRAP(reroute.fileName())
      .PARAM(res)
      ;
  }

  HOOK_END



  return res;
}

BOOL WINAPI usvfs::hooks::MoveFileExW(LPCWSTR lpExistingFileName,
                                      LPCWSTR lpNewFileName,
                                      DWORD dwFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::FILEOP_GROUP)

  auto context = HookContext::readAccess();

  RerouteW readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
  RerouteW writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
  PRE_REALCALL
  res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), dwFlags);
  POST_REALCALL

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res);
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetCurrentDirectoryW(DWORD nBufferLength,
                                                LPWSTR lpBuffer)
{
  DWORD res = FALSE;

  HOOK_START

  PRE_REALCALL
  res = ::GetCurrentDirectoryW(nBufferLength, lpBuffer);
  POST_REALCALL

  if (false) {
    LOG_CALL().PARAMWRAP(lpBuffer).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::SetCurrentDirectoryW(LPCWSTR lpPathName)
{
  BOOL res = FALSE;

  HOOK_START

  PRE_REALCALL
  res = ::SetCurrentDirectoryW(lpPathName);
  POST_REALCALL

  LOG_CALL().PARAMWRAP(lpPathName).PARAM(res);

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetFullPathNameW(LPCWSTR lpFileName
                                            , DWORD nBufferLength
                                            , LPWSTR lpBuffer
                                            , LPWSTR *lpFilePart)
{
#pragma message("gets called with already-rerouted filename?")
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FULL_PATHNAME)

#pragma message("this doesn't cover the case where the caller is calling gfpn once with bufferlength 0 and then allocates a precisely fitting buffer")
#pragma message("also, this returns a virtualised path and thus isn't transparent")

  // nothing to do here? Maybe if current directory is virtualised
  PRE_REALCALL
  res = ::GetFullPathNameW(lpFileName, nBufferLength, lpBuffer,
                           lpFilePart);
  POST_REALCALL
/*
  RerouteW reroute = RerouteW::create(HookContext::readAccess(),
                                      callContext, lpBuffer);
  if (reroute.wasRerouted()) {
    size_t len = wcslen(reroute.fileName());
    if ((nBufferLength > 0) && (lpBuffer != nullptr)) {
      size_t copyCount = std::min<size_t>(nBufferLength, len + 1);
      ush::wcsncpy_sz(lpBuffer, reroute.fileName(), copyCount);
      if (lpFilePart != nullptr) {
        *lpFilePart = winapi::ex::wide::GetBaseName(lpBuffer);
        if (**lpFilePart == L'\0') {
          // lpBuffer is a directory
          *lpFilePart = nullptr;
        }
      }
    }
    if (len <= nBufferLength) {
      res = static_cast<DWORD>(len);
    } else {
      res = static_cast<DWORD>(len) + 1;
    }

    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAM(nBufferLength)
        .PARAM(lpBuffer)
        .PARAM(res);
  }
*/
  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetModuleFileNameW(HMODULE hModule
                                              , LPWSTR lpFilename
                                              , DWORD nSize)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::ALL_GROUPS)

  PRE_REALCALL
  res = ::GetModuleFileNameW(hModule, lpFilename, nSize);
  POST_REALCALL

  if (res != 0) {
    // on success

    // TODO: test if the filename is within a mapped directory. If so, rewrite it to be in the mapped-to directory
    //  -> reverseReroute...
  }

  if (callContext.active()) {
    LOG_CALL()
        .PARAM(hModule)
        .addParam("lpFilename", usvfs::log::Wrap<LPCWSTR>((res != 0UL) ? lpFilename : L"<not set>"))
        .PARAM(nSize)
        .PARAM(res);
  }

  HOOK_END

  return res;
}


VOID WINAPI usvfs::hooks::ExitProcess(UINT exitCode)
{
  HOOK_START

  {
    HookContext::Ptr context = HookContext::writeAccess();

    std::vector<std::future<int>> &delayed = context->delayed();

    if (!delayed.empty()) {
      // ensure all delayed tasks are completed before we exit the process
      for (std::future<int> &delayed : HookContext::writeAccess()->delayed()) {
        delayed.get();
      }
      delayed.clear();
    }
  }

  // exitprocess doesn't return so logging the call after the real call doesn't make much sense.
  // nor does any pre/post call macro
  LOG_CALL().PARAM(exitCode);

  HookManager::instance().removeHook("ExitProcess");
  PRE_REALCALL
  ExitProcess(exitCode);
  POST_REALCALL

  HOOK_END
}

