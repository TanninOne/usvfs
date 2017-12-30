#include "kernel32.h"
#include "sharedids.h"
#include <loghelpers.h>
#include "../hookmanager.h"
#include "../hookcontext.h"
#include "../hookcallcontext.h"
#include <usvfs.h>
#include <inject.h>
#include <winapi.h>
#include <winbase.h>
#include <shellapi.h>
#include <stringutils.h>
#include <stringcast.h>
#include <set>
#include <sstream>
#include <shlwapi.h>

#if 1
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#else
namespace fs = std::tr2::sys;
#include <filesystem>
#endif

namespace ush = usvfs::shared;
using ush::string_cast;
using ush::CodePage;

class RerouteW
{
  std::wstring m_Buffer{};
  std::wstring m_RealPath{};
  bool m_Rerouted{false};
  LPCWSTR m_FileName{nullptr};

  usvfs::RedirectionTree::NodePtrT m_FileNode;

public:
  RerouteW() = default;

  RerouteW(RerouteW &&reference)
    : m_Buffer(reference.m_Buffer)
    , m_RealPath(reference.m_RealPath)
    , m_Rerouted(reference.m_Rerouted)
    , m_FileNode(reference.m_FileNode)
  {
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
  }

  RerouteW &operator=(RerouteW &&reference)
  {
    m_Buffer   = std::move(reference.m_Buffer);
    m_RealPath = std::move(reference.m_RealPath);
    m_Rerouted = reference.m_Rerouted;
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
    m_FileNode = reference.m_FileNode;
    return *this;
  }

  RerouteW(const RerouteW &reference) = delete;
  RerouteW &operator=(const RerouteW &) = delete;

  LPCWSTR fileName() const
  {
    return m_FileName;
  }

  const std::wstring &buffer() const
  {
    return m_Buffer;
  }

  bool wasRerouted() const
  {
    return m_Rerouted;
  }

  void insertMapping(const usvfs::HookContext::Ptr &context)
  {
    m_FileNode = context->redirectionTable().addFile(
        m_RealPath, usvfs::RedirectionDataLocal(
                        string_cast<std::string>(m_FileName, CodePage::UTF8)));
  }

  void removeMapping()
  {
    if (m_FileNode.get() != nullptr) {
      m_FileNode->removeFromTree();
    } else {
      spdlog::get("usvfs")
          ->warn("Node not removed: {}", string_cast<std::string>(m_FileName));
    }
  }

  static fs::path absolute_path(const wchar_t *inPath)
  {
    if (ush::startswith(inPath, LR"(\\?\)") || ush::startswith(inPath, LR"(\??\)")) {
      inPath += 4;
      return inPath;
    }
    else if ((ush::startswith(inPath, LR"(\\localhost\)") || ush::startswith(inPath, LR"(\\127.0.0.1\)")) && inPath[13] == L'$') {
      std::wstring newPath;
      newPath += towupper(inPath[12]);
      newPath += L':';
      newPath += &inPath[14];
      return newPath;
    }
    else if (inPath[0] == L'\0' || inPath[1] == L':') {
      return inPath;
    }
    usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FULL_PATHNAME);
    return winapi::wide::getFullPathName(inPath).first;
  }

  static fs::path canonize_path(const fs::path& inPath)
  {
    fs::path p = inPath.lexically_normal();
    if (p.filename_is_dot())
      p = p.remove_filename();
    return p.make_preferred();
  }

  static RerouteW create(const usvfs::HookContext::ConstPtr &context,
                         const usvfs::HookCallContext &callContext,
                         const wchar_t *inPath, bool inverse = false)
  {
    RerouteW result;
    if ((inPath != nullptr) && (inPath[0] != L'\0')
        && !ush::startswith(inPath, L"hid#")) {
      result.m_Buffer   = std::wstring(inPath);
      result.m_Rerouted = false;
      if (callContext.active()) {
        fs::path lookupPath = canonize_path(absolute_path(inPath));

        const usvfs::RedirectionTreeContainer &table
            = inverse ? context->inverseTable() : context->redirectionTable();
        result.m_FileNode = table->findNode(lookupPath);

        if (result.m_FileNode.get()
          && (!result.m_FileNode->data().linkTarget.empty() || result.m_FileNode->isDirectory())) {
          if (!result.m_FileNode->data().linkTarget.empty()) {
            result.m_Buffer = string_cast<std::wstring>(
              result.m_FileNode->data().linkTarget.c_str(), CodePage::UTF8);
          }
          else
          {
            result.m_Buffer = result.m_FileNode->path().wstring();
          }
          if (result.m_Buffer.length() >= MAX_PATH && !ush::startswith(result.m_Buffer.c_str(), LR"(\\?\)"))
            result.m_Buffer = LR"(\\?\)" + result.m_Buffer;
          result.m_Rerouted = true;
        }
      }
      std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
      result.m_FileName = result.m_Buffer.c_str();
    }
    return result;
  }

  static RerouteW createNew(const usvfs::HookContext::ConstPtr &context,
                            const usvfs::HookCallContext &callContext,
                            LPCWSTR inPath)
  {
    UNUSED_VAR(callContext);
    RerouteW result;
    result.m_Rerouted = false;

    if ((inPath != nullptr) && (inPath[0] != L'\0')
        && !ush::startswith(inPath, L"hid#")) {
      result.m_Buffer   = inPath;
      fs::path lookupPath = absolute_path(inPath);
      result.m_RealPath = lookupPath.c_str();
      lookupPath = canonize_path(lookupPath);

      FindCreateTarget visitor;
      usvfs::RedirectionTree::VisitorFunction visitorWrapper = [&](
          const usvfs::RedirectionTree::NodePtrT &node) { visitor(node); };
      context->redirectionTable()->visitPath(lookupPath, visitorWrapper);
      if (visitor.target.get() != nullptr) {
        // the visitor has found the last (deepest in the directory hierarchy)
        // create-target
        fs::path relativePath
            = ush::make_relative(visitor.target->path(), lookupPath);
        result.m_Buffer = (fs::path(visitor.target->data().linkTarget.c_str())
                           / relativePath)
                              .wstring();
        try {
          usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::ALL_GROUPS);
          winapi::ex::wide::createPath(
              fs::path(result.m_Buffer).parent_path().wstring().c_str());
        } catch (const std::exception &e) {
          spdlog::get("hooks")
              ->error("failed to create {}: {}",
                      ush::string_cast<std::string>(result.m_Buffer), e.what());
        }

        result.m_Rerouted = true;
      }
    }

    result.m_FileName = result.m_Buffer.c_str();

    return result;
  }

private:
  struct FindCreateTarget {
    usvfs::RedirectionTree::NodePtrT target;
    void operator()(usvfs::RedirectionTree::NodePtrT node)
    {
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

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res = ::LoadLibraryW(reroute.fileName());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::LoadLibraryA(LPCSTR lpFileName)
{
  return usvfs::hooks::LoadLibraryW(
      ush::string_cast<std::wstring>(lpFileName).c_str());
}

HMODULE WINAPI usvfs::hooks::LoadLibraryExW(LPCWSTR lpFileName, HANDLE hFile,
                                            DWORD dwFlags)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::LOAD_LIBRARY)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);
  PRE_REALCALL
  res = ::LoadLibraryExW(reroute.fileName(), hFile, dwFlags);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAM(lpFileName).PARAM(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::LoadLibraryExA(LPCSTR lpFileName, HANDLE hFile,
                                            DWORD dwFlags)
{
  return usvfs::hooks::LoadLibraryExW(
      ush::string_cast<std::wstring>(lpFileName).c_str(), hFile, dwFlags);
}

/// determine name of the binary to run based on parameters for createprocess
std::wstring getBinaryName(LPCWSTR applicationName, LPCWSTR lpCommandLine)
{
  if (applicationName != nullptr) {
    std::pair<std::wstring, std::wstring> fullPath
        = winapi::wide::getFullPathName(applicationName);
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

BOOL WINAPI usvfs::hooks::CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)
  if (!callContext.active()) {
    return ::CreateProcessA(
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  }

  // remember if the caller wanted the process to be suspended. If so, we don't
  // resume when
  // we're done
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  dwCreationFlags |= CREATE_SUSPENDED;

  std::string cmdline;
  RerouteW applicationReroute;

  std::wstring dllPath;
  USVFSParameters callParameters;

  { // scope for context lock
    auto context = READ_CONTEXT();

    if (lpCommandLine != nullptr) {
      // decompose command line
      int argc             = 0;
      std::wstring arglist = ush::string_cast<std::wstring>(lpCommandLine);
      LPWSTR *argv = ::CommandLineToArgvW(arglist.c_str(), &argc);
      ON_BLOCK_EXIT([argv]() { LocalFree(argv); });

      RerouteW cmdReroute = RerouteW::create(context, callContext, argv[0]);

      // find start of "real" arguments in lpCommandLine instead of using argv[1], ...
      // because CommandLineToArgvW can change quoted/escaped sequences and we
      // want to preserve them
      LPCSTR args = lpCommandLine;
      for (; *args && *args != ' '; ++args)
        if (*args == '"') {
          int escaped = 0;
          for (++args; *args && (*args != '"' || escaped % 2 != 0); ++args)
            escaped = *args == '\\' ? escaped + 1 : 0;
        }

      // recompose command line
      std::stringstream stream;
      stream << "\"" << ush::string_cast<std::string>(cmdReroute.fileName(), CodePage::UTF8) << "\"" << args;
      cmdline = stream.str();
    }

    applicationReroute = RerouteW::create(
        context, callContext,
        lpApplicationName != nullptr
            ? ush::string_cast<std::wstring>(lpApplicationName).c_str()
            : nullptr);

    dllPath        = context->dllPath();
    callParameters = context->callParameters();
  }

  PRE_REALCALL
  LPCSTR appName = nullptr;
  std::string appNameBuffer;
  if (applicationReroute.fileName() != nullptr) {
    appNameBuffer = ush::string_cast<std::string>(applicationReroute.fileName(), CodePage::UTF8);
    appName = appNameBuffer.c_str();
  }
  res = ::CreateProcessA(
      appName,
      lpCommandLine != nullptr ? &cmdline[0] : nullptr, lpProcessAttributes,
      lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
      lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  POST_REALCALL

  // hook unless blacklisted
  // TODO implement process blacklisting. Currently disabled because storing in
  // redirection-tree doesn't work and makes no sense
  //  std::wstring binaryName = getBinaryName(applicationReroute.fileName(),
  //  lpCommandLine);
  //  bool blacklisted =
  //  context->redirectionTable()->testProcessBlacklisted(usvfs::shared::toNarrow(binaryName.c_str()).c_str());
  bool blacklisted = false;
  if (!blacklisted) {
    try {
      injectProcess(dllPath, callParameters, *lpProcessInformation);
    } catch (const std::exception &e) {
      spdlog::get("hooks")->error("failed to inject into {0}: {1}",
                                  log::wrap(applicationReroute.fileName()),
                                  e.what());
    }
  }

  // resume unless process is suposed to start suspended
  if (!susp && (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    spdlog::get("hooks")->error("failed to inject into spawned process");
    res = FALSE;
  }

  LOG_CALL()
      .PARAM(applicationReroute.fileName())
      .PARAM(cmdline)
      .PARAM(blacklisted)
      .PARAM(res);

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)
  if (!callContext.active()) {
    return ::CreateProcessW(
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  }

  // remember if the caller wanted the process to be suspended. If so, we
  // don't resume when we're done
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  dwCreationFlags |= CREATE_SUSPENDED;

  std::wstring cmdline;
  RerouteW applicationReroute;

  std::wstring dllPath;
  USVFSParameters callParameters;

  { // scope for context lock
    auto context = READ_CONTEXT();

    if (lpCommandLine != nullptr) {
      // decompose command line
      int argc     = 0;
      LPWSTR *argv = ::CommandLineToArgvW(lpCommandLine, &argc);
      ON_BLOCK_EXIT([argv]() { LocalFree(argv); });

      RerouteW cmdReroute = RerouteW::create(context, callContext, argv[0]);

      // find start of "real" arguments in lpCommandLine instead of using argv[1], ...
      // because CommandLineToArgvW can change quoted/escaped sequences and we
      // want to preserve them
      LPCWSTR args = lpCommandLine;
      for (; *args && *args != ' '; ++args)
      if (*args == '"') {
        int escaped = 0;
        for (++args; *args && (*args != '"' || escaped % 2 != 0); ++args)
          escaped = *args == '\\' ? escaped + 1 : 0;
      }

      // recompose command line
      std::wstringstream stream;
      stream << L"\"" << cmdReroute.fileName() << L"\"" << args;
      cmdline = stream.str();
    }

    applicationReroute
        = RerouteW::create(context, callContext, lpApplicationName);

    dllPath        = context->dllPath();
    callParameters = context->callParameters();
  }

  PRE_REALCALL
  res = ::CreateProcessW(
      applicationReroute.fileName(),
      lpCommandLine != nullptr ? &cmdline[0] : nullptr, lpProcessAttributes,
      lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
      lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  POST_REALCALL

  // hook unless blacklisted
  // TODO implement process blacklisting. Currently disabled because storing in
  // redirection-tree doesn't work and makes no sense
  //  std::wstring binaryName = getBinaryName(applicationReroute.fileName(),
  //  lpCommandLine);
  //  bool blacklisted =
  //  context->redirectionTable()->testProcessBlacklisted(usvfs::shared::toNarrow(binaryName.c_str()).c_str());
  bool blacklisted = false;
  if (!blacklisted) {
    try {
      injectProcess(dllPath, callParameters, *lpProcessInformation);
    } catch (const std::exception &e) {
      spdlog::get("hooks")
          ->error("failed to inject into {0}: {1}",
                  lpApplicationName != nullptr
                      ? log::wrap(applicationReroute.fileName())
                      : log::wrap(static_cast<LPCWSTR>(lpCommandLine)),
                  e.what());
    }
  }

  // resume unless process is suposed to start suspended
  if (!susp && (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    spdlog::get("hooks")->error("failed to inject into spawned process");
    res = FALSE;
  }

  LOG_CALL()
      .PARAM(applicationReroute.fileName())
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

HANDLE WINAPI usvfs::hooks::CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  return usvfs::hooks::CreateFileW(
      ush::string_cast<std::wstring>(lpFileName).c_str(), dwDesiredAccess,
      dwShareMode, lpSecurityAttributes, dwCreationDisposition,
      dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI usvfs::hooks::CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  HANDLE res = INVALID_HANDLE_VALUE;
  DWORD error = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active()) {
    return ::CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
  }

  bool storePath = false;
  if ((dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS) != 0UL) {
    // this may be an attempt to open a directory handle for iterating.
    // If so we need to treat it a little bit differently
    bool isDir  = false;
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
      isDir            = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL;
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

  bool create = false;

  RerouteW reroute;
  {
    auto context = READ_CONTEXT();
    reroute      = RerouteW::create(context, callContext, lpFileName);
    if (((dwCreationDisposition == CREATE_ALWAYS)
         || (dwCreationDisposition == CREATE_NEW))
        && !reroute.wasRerouted() && !fileExists(lpFileName)) {
      // the file will be created so now we need to know where
      reroute = RerouteW::createNew(context, callContext, lpFileName);
      create  = reroute.wasRerouted();

      if (create) {
        fs::path target(reroute.fileName());
        winapi::ex::wide::createPath(target.parent_path().wstring().c_str(),
                                     lpSecurityAttributes);
      }
    }
  }

  PRE_REALCALL
  res = ::CreateFileW(reroute.fileName(), dwDesiredAccess, dwShareMode,
                      lpSecurityAttributes, dwCreationDisposition,
                      dwFlagsAndAttributes, hTemplateFile);
  POST_REALCALL

  if (res == INVALID_HANDLE_VALUE) {
    switch (dwCreationDisposition) {
    case 3:
    case 5:
      error = ERROR_FILE_NOT_FOUND;
      break;
    default:
      error = ::GetLastError();
    }
  }

  if (create && (res != INVALID_HANDLE_VALUE)) {
    spdlog::get("hooks")
        ->info("add file to vfs: {}",
               ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8));
    // new file was created in a mapped directory, insert to vitual structure
    reroute.insertMapping(WRITE_CONTEXT());
  }

  if ((res != INVALID_HANDLE_VALUE) && storePath) {
    // store the original search path for use during iteration
    WRITE_CONTEXT()
        ->customData<SearchHandleMap>(SearchHandles)[res]
        = lpFileName;
  }

  if (storePath || reroute.wasRerouted()) {
    LOG_CALL()
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(dwDesiredAccess)
      .PARAMHEX(dwCreationDisposition)
      .PARAMHEX(dwFlagsAndAttributes)
      .PARAMHEX(res)
      .PARAMHEX(error);
  }
  HOOK_END

  ::SetLastError(error);

  return res;
}

HANDLE WINAPI usvfs::hooks::CreateFile2(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams)
{
  HANDLE res = INVALID_HANDLE_VALUE;
  DWORD error = 0;

  typedef HANDLE(WINAPI * CreateFile2_t)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);

  HMODULE kernelbase = ::GetModuleHandle(L"kernelbase.dll");
  HMODULE kernel = ::GetModuleHandle(L"kernel32.dll");
  CreateFile2_t dCreateFile2 = NULL;
  if (kernelbase != NULL)
    dCreateFile2 = (CreateFile2_t)::GetProcAddress(kernelbase, "CreateFile2");
  if (dCreateFile2 == NULL && kernel != NULL)
    dCreateFile2 = (CreateFile2_t)::GetProcAddress(kernel, "CreateFile2");
  if (dCreateFile2 == NULL) return res;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active()) {
    return dCreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
  }

  bool storePath = false;
  bool isDir = false;
  if (pCreateExParams != nullptr) {
    if ((pCreateExParams->dwFileFlags & FILE_FLAG_BACKUP_SEMANTICS) != 0UL) {
      // this may be an attempt to open a directory handle for iterating.
      // If so we need to treat it a little bit differently
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
          return dCreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
        }
        else {
          // if its a directory and it only exists "virtually" then we need to
          // store the path for when the caller iterates the directory
          storePath = true;
        }
      }
    }
  }

  bool create = false;

  RerouteW reroute;
  {
    auto context = READ_CONTEXT();
    reroute = RerouteW::create(context, callContext, lpFileName);
    if (((dwCreationDisposition == CREATE_ALWAYS)
      || (dwCreationDisposition == CREATE_NEW) || (isDir && storePath))
      && !reroute.wasRerouted() && !fileExists(lpFileName)) {
      // the file will be created so now we need to know where
      reroute = RerouteW::createNew(context, callContext, lpFileName);
      create = (reroute.wasRerouted() || (isDir && storePath));

      if (create) {
        fs::path target(reroute.fileName());
        if (pCreateExParams != nullptr)
          winapi::ex::wide::createPath(target.parent_path().wstring().c_str(),
            pCreateExParams->lpSecurityAttributes);
        else
          winapi::ex::wide::createPath(target.parent_path().wstring().c_str());
      }
    }
  }

  PRE_REALCALL
  res = dCreateFile2(reroute.fileName(), dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
  POST_REALCALL

  if (res == INVALID_HANDLE_VALUE) {
    switch (dwCreationDisposition) {
    case 3:
    case 5:
      error = ERROR_FILE_NOT_FOUND;
      break;
    default:
      error = ::GetLastError();
    }
  }

  if (create && (res != INVALID_HANDLE_VALUE)) {
    spdlog::get("hooks")
      ->info("add file to vfs: {}",
        ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8));
    // new file was created in a mapped directory, insert to vitual structure
    reroute.insertMapping(WRITE_CONTEXT());
  }

  if ((res != INVALID_HANDLE_VALUE) && storePath) {
    // store the original search path for use during iteration
    WRITE_CONTEXT()
      ->customData<SearchHandleMap>(SearchHandles)[res]
      = lpFileName;
  }

  if (storePath || reroute.wasRerouted()) {
    DWORD dwFileAttributes = 0;
    DWORD dwFileFlags = 0;
    if (pCreateExParams != nullptr) {
      dwFileAttributes = pCreateExParams->dwFileAttributes;
      dwFileFlags = pCreateExParams->dwFileFlags;
    }
    LOG_CALL()
      .PARAM(lpFileName)
      .PARAM(reroute.fileName())
      .PARAM(isDir)
      .PARAM(storePath)
      .PARAMHEX(dwDesiredAccess)
      .PARAMHEX(dwCreationDisposition)
      .PARAMHEX(dwFileAttributes)
      .PARAMHEX(dwFileFlags)
      .PARAMHEX(res)
      .PARAMHEX(error);
  }
  HOOK_END

  ::SetLastError(error);

  return res;
}

BOOL WINAPI usvfs::hooks::GetFileAttributesExA(
  LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
  LPVOID lpFileInformation)
{
  return usvfs::hooks::GetFileAttributesExW(ush::string_cast<std::wstring>(lpFileName).c_str(), fInfoLevelId, lpFileInformation);
}

BOOL WINAPI usvfs::hooks::GetFileAttributesExW(
    LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);
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

DWORD WINAPI usvfs::hooks::GetFileAttributesA(LPCSTR lpFileName)
{
  return usvfs::hooks::GetFileAttributesW(ush::string_cast<std::wstring>(lpFileName).c_str());
}

DWORD WINAPI usvfs::hooks::GetFileAttributesW(LPCWSTR lpFileName)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);
  PRE_REALCALL
  res = ::GetFileAttributesW(reroute.fileName());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(callContext.lastError());
    ;
  }

  HOOK_ENDP(usvfs::log::wrap(lpFileName));

  return res;
}

DWORD WINAPI usvfs::hooks::SetFileAttributesW(
	LPCWSTR lpFileName, DWORD dwFileAttributes)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);
  PRE_REALCALL
  res = ::SetFileAttributesW(reroute.fileName(), dwFileAttributes);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::DeleteFileW(LPCWSTR lpFileName)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::DELETE_FILE)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  if (reroute.wasRerouted()) {
    res = ::DeleteFileW(reroute.fileName());
  } else {
    res = ::DeleteFileW(lpFileName);
  }
  POST_REALCALL

  if (reroute.wasRerouted()) {
    reroute.removeMapping();
    LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::DeleteFileA(LPCSTR lpFileName)
{
  return usvfs::hooks::DeleteFileW(
      ush::string_cast<std::wstring>(lpFileName).c_str());
}

BOOL WINAPI usvfs::hooks::MoveFileA(LPCSTR lpExistingFileName,
                                    LPCSTR lpNewFileName)
{
  return usvfs::hooks::MoveFileW(
      ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
      ush::string_cast<std::wstring>(lpNewFileName).c_str());
}

BOOL WINAPI usvfs::hooks::MoveFileW(LPCWSTR lpExistingFileName,
                                    LPCWSTR lpNewFileName)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
  }

  PRE_REALCALL
  res = ::MoveFileW(readReroute.fileName(), writeReroute.fileName());
  POST_REALCALL

  if (res) {
    if (readReroute.wasRerouted()) {
      readReroute.removeMapping();
    }

    if (writeReroute.wasRerouted()) {
      writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res)
        .PARAM(::GetLastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::MoveFileExA(LPCSTR lpExistingFileName,
                                      LPCSTR lpNewFileName, DWORD dwFlags)
{
  return MoveFileExW(ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
                     ush::string_cast<std::wstring>(lpNewFileName).c_str(),
                     dwFlags);
}

BOOL WINAPI usvfs::hooks::MoveFileExW(LPCWSTR lpExistingFileName,
                                      LPCWSTR lpNewFileName, DWORD dwFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
  }

  PRE_REALCALL
  res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), dwFlags);
  POST_REALCALL

  if (res) {
    if (readReroute.wasRerouted()) {
      readReroute.removeMapping();
    }

    if (writeReroute.wasRerouted()) {
      writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res)
        .PARAM(::GetLastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::CopyFileA(LPCSTR lpExistingFileName,
                                    LPCSTR lpNewFileName, BOOL bFailIfExists)
{
  return CopyFileW(ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
                   ush::string_cast<std::wstring>(lpNewFileName).c_str(),
                   bFailIfExists);
}

BOOL WINAPI usvfs::hooks::CopyFileW(LPCWSTR lpExistingFileName,
                                    LPCWSTR lpNewFileName, BOOL bFailIfExists)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
  }

  PRE_REALCALL
  res = ::CopyFileW(readReroute.fileName(), writeReroute.fileName(),
                    bFailIfExists);
  POST_REALCALL

  if (res) {
    if (writeReroute.wasRerouted()) {
      writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res)
        .PARAM(::GetLastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::CopyFileExA(LPCSTR lpExistingFileName,
                                      LPCSTR lpNewFileName,
                                      LPPROGRESS_ROUTINE lpProgressRoutine,
                                      LPVOID lpData, LPBOOL pbCancel,
                                      DWORD dwCopyFlags)
{
  return ::CopyFileExW(
      ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
      ush::string_cast<std::wstring>(lpNewFileName).c_str(), lpProgressRoutine,
      lpData, pbCancel, dwCopyFlags);
}

BOOL WINAPI usvfs::hooks::CopyFileExW(LPCWSTR lpExistingFileName,
                                      LPCWSTR lpNewFileName,
                                      LPPROGRESS_ROUTINE lpProgressRoutine,
                                      LPVOID lpData, LPBOOL pbCancel,
                                      DWORD dwCopyFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
  }

  PRE_REALCALL
  res = ::CopyFileExW(readReroute.fileName(), writeReroute.fileName(),
                      lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
  POST_REALCALL

  if (res) {
    if (writeReroute.wasRerouted()) {
      writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res)
        .PARAM(::GetLastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetCurrentDirectoryA(DWORD nBufferLength,
                                                LPSTR lpBuffer)
{
  std::wstring buffer;
  buffer.resize(nBufferLength);
  DWORD res = usvfs::hooks::GetCurrentDirectoryW(nBufferLength, &buffer[0]);

  if (res > 0) {
      res = WideCharToMultiByte(CP_ACP, 0, buffer.c_str(), res+1,
                                lpBuffer, nBufferLength, nullptr, nullptr);
  }

  return res;
}

DWORD WINAPI usvfs::hooks::GetCurrentDirectoryW(DWORD nBufferLength,
                                                LPWSTR lpBuffer)
{
  DWORD res = FALSE;

  HOOK_START

  auto context = READ_CONTEXT();
  std::wstring actualCWD = context->customData<std::wstring>(ActualCWD);

  if (actualCWD.empty()) {
    PRE_REALCALL
    res = ::GetCurrentDirectoryW(nBufferLength, lpBuffer);
    POST_REALCALL
  } else {
    ush::wcsncpy_sz(
        lpBuffer, &actualCWD[0],
        std::min(static_cast<size_t>(nBufferLength), actualCWD.size() + 1));

    // yupp, that's how GetCurrentDirectory actually works...
    if (actualCWD.size() < nBufferLength) {
      res = static_cast<DWORD>(actualCWD.size());
    } else {
      res = static_cast<DWORD>(actualCWD.size() + 1);
    }
  }

  if (!actualCWD.empty()) {
    LOG_CALL().PARAMWRAP(lpBuffer).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::SetCurrentDirectoryA(LPCSTR lpPathName) {
  return usvfs::hooks::SetCurrentDirectoryW(
      ush::string_cast<std::wstring>(lpPathName).c_str());
}

BOOL WINAPI usvfs::hooks::SetCurrentDirectoryW(LPCWSTR lpPathName)
{
  BOOL res = FALSE;

  HOOK_START

  std::wstring finalRoute;
  BOOL found = FALSE;

  auto context = READ_CONTEXT();

  WCHAR processDir[MAX_PATH];
  if (::GetModuleFileNameW(NULL, processDir, MAX_PATH) != 0 && ::PathRemoveFileSpecW(processDir)) {
    WCHAR processName[MAX_PATH];
    ::GetModuleFileNameW(NULL, processName, MAX_PATH);
    fs::path process(processName);
    fs::path routedName = lpPathName / process.filename();
    RerouteW rerouteTest = RerouteW::create(context, callContext, routedName.wstring().c_str());
    if (rerouteTest.wasRerouted()) {
      std::wstring reroutedPath = rerouteTest.fileName();
      if (routedName.wstring().find(processDir) != std::string::npos) {
        fs::path finalPath(reroutedPath);
        finalRoute = finalPath.parent_path().wstring();
        found = TRUE;
      }
    }
  }

  if (!found) {
    RerouteW reroute = RerouteW::create(context, callContext, lpPathName);
    finalRoute = reroute.fileName();
  }

  PRE_REALCALL
  res = ::SetCurrentDirectoryW(finalRoute.c_str());
  POST_REALCALL

  if (res) {
    context->customData<std::wstring>(ActualCWD) = lpPathName;
  }

  LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(finalRoute.c_str()).PARAM(res);

  HOOK_END

  return res;
}


DLLEXPORT BOOL WINAPI usvfs::hooks::CreateDirectoryW(
    LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  BOOL res = FALSE;
  HOOK_START
  RerouteW reroute
      = RerouteW::create(READ_CONTEXT(), callContext, lpPathName);

  PRE_REALCALL
  if (reroute.wasRerouted()) {
    // the intermediate directories may exist in the original directory but not
    // in the rerouted location so do a recursive create
    winapi::ex::wide::createPath(reroute.fileName(), lpSecurityAttributes);
    res = TRUE;
  } else {
    res = ::CreateDirectoryW(lpPathName, lpSecurityAttributes);
  }
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res);
  }
  HOOK_END

  return res;
}

DLLEXPORT BOOL WINAPI usvfs::hooks::RemoveDirectoryW(
	LPCWSTR lpPathName)
{

	BOOL res = FALSE;

	HOOK_START_GROUP(MutExHookGroup::DELETE_FILE)

	RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpPathName);

	PRE_REALCALL
	if (reroute.wasRerouted()) {
		res = ::RemoveDirectoryW(reroute.fileName());
	}
	else {
		res = ::RemoveDirectoryW(lpPathName);
	}
	POST_REALCALL

	if (reroute.wasRerouted()) {
		reroute.removeMapping();
		LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res);
	}

	HOOK_END

	return res;
}


DWORD WINAPI usvfs::hooks::GetFullPathNameW(LPCWSTR lpFileName,
                                            DWORD nBufferLength,
                                            LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FULL_PATHNAME)

  auto context = READ_CONTEXT();

  std::wstring actualCWD = context->customData<std::wstring>(ActualCWD);
  std::wstring temp;
  if (actualCWD.empty() || fs::path(lpFileName).is_absolute()) {
    temp = lpFileName;
  } else {
    temp = (fs::wpath(actualCWD) / lpFileName).wstring();
  }
  PRE_REALCALL
  res = ::GetFullPathNameW(temp.c_str(), nBufferLength, lpBuffer, lpFilePart);
  POST_REALCALL

  // nothing to do here? Maybe if current directory is virtualised
  HOOK_END

  if (false) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(lpBuffer)
        .PARAM(res)
        .PARAM(::GetLastError());
  }

  return res;
}


DWORD WINAPI usvfs::hooks::GetModuleFileNameW(HMODULE hModule,
                                              LPWSTR lpFilename, DWORD nSize)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::ALL_GROUPS)
  PRE_REALCALL
  res = ::GetModuleFileNameW(hModule, lpFilename, nSize);
  POST_REALCALL
  if ((res != 0) && callContext.active()) {
    RerouteW reroute
        = RerouteW::create(READ_CONTEXT(), callContext, lpFilename, true);
    if (reroute.wasRerouted()) {
      DWORD reroutedSize = static_cast<DWORD>(reroute.buffer().size());
      if (reroutedSize >= nSize) {
        callContext.updateLastError(ERROR_INSUFFICIENT_BUFFER);
        reroutedSize = nSize - 1;
      }
      // res can't be bigger than nSize-1 at this point
      if (reroutedSize > 0) {
        if (reroutedSize < res) {
          // zero out the string windows has previously written to
          memset(lpFilename, '\0', std::min(res, nSize) * sizeof(wchar_t));
        }
        // this truncates the string if the buffer is too small
        ush::wcsncpy_sz(lpFilename, reroute.fileName(), reroutedSize + 1);
      }
      res = reroutedSize;
    }

    if (reroute.wasRerouted()) {
      LOG_CALL()
          .PARAM(hModule)
          .addParam("lpFilename", usvfs::log::Wrap<LPCWSTR>(
                      (res != 0UL) ? lpFilename : L"<not set>"))
          .PARAM(nSize)
          .PARAMHEX(::GetLastError())
          .PARAM(res);
    }
  }
  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetModuleFileNameA(HMODULE hModule,
                                              LPSTR lpFilename, DWORD nSize)
{
  std::unique_ptr<WCHAR[]> buffer(new WCHAR[nSize]);
  DWORD res = usvfs::hooks::GetModuleFileNameW(hModule, buffer.get(), nSize);
  if (res > 0) {
    WideCharToMultiByte(CP_ACP, 0, buffer.get(), -1,
                        lpFilename, nSize, nullptr, nullptr);
    if (res > nSize) {
      lpFilename[nSize - 1] = '\0';
    }
  }

  return res;
}

HMODULE WINAPI usvfs::hooks::GetModuleHandleW(LPCWSTR lpModuleName)
{
  HMODULE res = nullptr;

  HOOK_START_GROUP(MutExHookGroup::GET_MODULE_HANDLE)

  RerouteW reroute
      = RerouteW::create(READ_CONTEXT(), callContext, lpModuleName);
  PRE_REALCALL
  res = ::GetModuleHandleW(reroute.fileName());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

HMODULE WINAPI usvfs::hooks::GetModuleHandleA(LPCSTR lpModuleName)
{
  if (lpModuleName != nullptr) {
    return GetModuleHandleW(ush::string_cast<std::wstring>(lpModuleName).c_str());
  } else {
    return GetModuleHandleW(nullptr);
  }
}

BOOL WINAPI usvfs::hooks::GetModuleHandleExW(DWORD dwFlags,
                                             LPCWSTR lpModuleName,
                                             HMODULE *phModule)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::GET_MODULE_HANDLE)

  RerouteW reroute
      = RerouteW::create(READ_CONTEXT(), callContext, lpModuleName);
  PRE_REALCALL
  res = ::GetModuleHandleExW(dwFlags, reroute.fileName(), phModule);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName,
                                             HMODULE *phModule)
{
  if (lpModuleName != nullptr) {
    return usvfs::hooks::GetModuleHandleExW(
        dwFlags, ush::string_cast<std::wstring>(lpModuleName).c_str(),
        phModule);
  } else {
    return usvfs::hooks::GetModuleHandleExW(dwFlags, nullptr, phModule);
  }
}

BOOL WINAPI usvfs::hooks::GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::GET_FILE_VERSION)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lptstrFilename);
  PRE_REALCALL
  res = ::GetFileVersionInfoW(reroute.fileName(), dwHandle, dwLen, lpData);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hooks::GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::GET_FILE_VERSION)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lptstrFilename);
  PRE_REALCALL
  res = ::GetFileVersionInfoExW(dwFlags, reroute.fileName(), dwHandle, dwLen, lpData);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::GET_FILE_VERSION)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lptstrFilename);
  PRE_REALCALL
  res = ::GetFileVersionInfoSizeW(reroute.fileName(), lpdwHandle);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::GET_FILE_VERSION)

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lptstrFilename);
  PRE_REALCALL
  res = ::GetFileVersionInfoSizeExW(dwFlags, reroute.fileName(), lpdwHandle);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res);
  }

  HOOK_END

  return res;
}

HANDLE WINAPI usvfs::hooks::FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
	LPWIN32_FIND_DATAA origData = static_cast<LPWIN32_FIND_DATAA>(lpFindFileData);

	WIN32_FIND_DATAW tempData;
	HANDLE tempHandle = usvfs::hooks::FindFirstFileExW(ush::string_cast<std::wstring>(lpFileName).c_str(), fInfoLevelId, &tempData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	origData->dwFileAttributes = tempData.dwFileAttributes;
	origData->ftCreationTime = tempData.ftCreationTime;
	origData->ftLastAccessTime = tempData.ftLastAccessTime;
	origData->ftLastWriteTime = tempData.ftLastWriteTime;
	origData->nFileSizeHigh = tempData.nFileSizeHigh;
	origData->nFileSizeLow = tempData.nFileSizeLow;
	origData->dwReserved0 = tempData.dwReserved0;
	origData->dwReserved1 = tempData.dwReserved1;
	strncpy_s(origData->cFileName, ush::string_cast<std::string>(tempData.cFileName).c_str(), _TRUNCATE);
	strncpy_s(origData->cAlternateFileName, ush::string_cast<std::string>(tempData.cAlternateFileName).c_str(), _TRUNCATE);
	return tempHandle;
}

HANDLE WINAPI usvfs::hooks::FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  HOOK_START_GROUP(MutExHookGroup::SEARCH_FILES)

  // We need to do some trickery here, since we only want to use the hooked NtQueryDirectoryFile for rerouted locations we need to check if the Directory path has been routed instead of the full path.
  fs::path p(lpFileName);
  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, (p.parent_path().wstring()).c_str());
  WCHAR appDataLocal[MAX_PATH];
  ::SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataLocal);
  fs::path temp = fs::path(appDataLocal) / "Temp";
  fs::path finalPath;
  if (reroute.wasRerouted()) {
    finalPath = reroute.fileName();
    finalPath /= p.filename().wstring();
  }

  PRE_REALCALL
  if (reroute.wasRerouted() || p.wstring().find(temp.wstring()) == std::string::npos) {
    res = ::FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if (res == INVALID_HANDLE_VALUE && !finalPath.empty())
      res = ::FindFirstFileExW(finalPath.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
  }
  else {
    //Force the mutEXHook to match NtQueryDirectoryFile so it calls the non hooked NtQueryDirectoryFile.
    FunctionGroupLock lock(MutExHookGroup::FIND_FILES);
    res = ::FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
  }
  POST_REALCALL

  if (res != INVALID_HANDLE_VALUE) {
  // store the original search path for use during iteration
  WRITE_CONTEXT()
      ->customData<SearchHandleMap>(SearchHandles)[res]
      = lpFileName;
  }

  LOG_CALL().PARAMWRAP(p.c_str()).PARAMWRAP(finalPath.c_str()).PARAM(res);

  HOOK_END

  return res;
}

HRESULT WINAPI usvfs::hooks::CopyFile2(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters)
{
  HRESULT res = E_FAIL;

  typedef HRESULT(WINAPI * CopyFile2_t)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS *);

  HMODULE kernelbase = ::GetModuleHandle(L"kernelbase.dll");
  HMODULE kernel = ::GetModuleHandle(L"kernel32.dll");
  CopyFile2_t dCopyFile2 = NULL;
  if (kernelbase != NULL)
    dCopyFile2 = (CopyFile2_t)::GetProcAddress(kernelbase, "CopyFile2");
  if (dCopyFile2 == NULL && kernel != NULL)
    dCopyFile2 = (CopyFile2_t)::GetProcAddress(kernel, "CopyFile2");
  if (dCopyFile2 == NULL) return res;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, pwszExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, pwszNewFileName);
  }

	PRE_REALCALL
    if (!readReroute.wasRerouted() && !writeReroute.wasRerouted()) {
        res = dCopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
    }
    else {
        res = dCopyFile2(readReroute.fileName(), writeReroute.fileName(), pExtendedParameters);
    }
    POST_REALCALL

  if (SUCCEEDED(res)) {
    if (writeReroute.wasRerouted()) {
      writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted()) {
    LOG_CALL()
      .PARAMWRAP(readReroute.fileName())
      .PARAMWRAP(writeReroute.fileName())
      .PARAM(res)
      .PARAM(::GetLastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hooks::GetPrivateProfileSectionNamesA(LPSTR lpszReturnBuffer, DWORD nSize, LPCSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

    if (!callContext.active()) {
      return ::GetPrivateProfileSectionNamesA(lpszReturnBuffer, nSize, lpFileName);
    }

  auto context = READ_CONTEXT();
  RerouteW reroute = RerouteW::create(context, callContext, ush::string_cast<std::wstring>(lpFileName).c_str());
  PRE_REALCALL
    res = ::GetPrivateProfileSectionNamesA(lpszReturnBuffer, nSize, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

    if (reroute.wasRerouted()) {
      LOG_CALL()
        .PARAMHEX(nSize)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
    }
  HOOK_END

    return res;
}

DWORD WINAPI usvfs::hooks::GetPrivateProfileSectionNamesW(LPWSTR lpszReturnBuffer, DWORD nSize, LPCWSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

    if (!callContext.active()) {
      return ::GetPrivateProfileSectionNamesW(lpszReturnBuffer, nSize, lpFileName);
    }

  auto context = READ_CONTEXT();
  RerouteW reroute = RerouteW::create(context, callContext, lpFileName);
  PRE_REALCALL
    res = ::GetPrivateProfileSectionNamesW(lpszReturnBuffer, nSize, reroute.fileName());
  POST_REALCALL

    if (reroute.wasRerouted()) {
      LOG_CALL()
        .PARAMHEX(nSize)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
    }
  HOOK_END

    return res;
}

DWORD WINAPI usvfs::hooks::GetPrivateProfileSectionA(LPCSTR lpAppName, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

    if (!callContext.active()) {
      return ::GetPrivateProfileSectionA(lpAppName, lpReturnedString, nSize, lpFileName);
    }

  auto context = READ_CONTEXT();
  RerouteW reroute = RerouteW::create(context, callContext, ush::string_cast<std::wstring>(lpFileName).c_str());
  PRE_REALCALL
    res = ::GetPrivateProfileSectionA(lpAppName, lpReturnedString, nSize, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

    if (reroute.wasRerouted()) {
      LOG_CALL()
        .PARAMHEX(nSize)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
    }
  HOOK_END

    return res;
}

DWORD WINAPI usvfs::hooks::GetPrivateProfileSectionW(LPCWSTR lpAppName, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

    if (!callContext.active()) {
      return ::GetPrivateProfileSectionW(lpAppName, lpReturnedString, nSize, lpFileName);
    }

  auto context = READ_CONTEXT();
  RerouteW reroute = RerouteW::create(context, callContext, lpFileName);
  PRE_REALCALL
    res = ::GetPrivateProfileSectionW(lpAppName, lpReturnedString, nSize, reroute.fileName());
  POST_REALCALL

    if (reroute.wasRerouted()) {
      LOG_CALL()
        .PARAMHEX(nSize)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(::GetLastError());
    }
  HOOK_END

    return res;
}

BOOL WINAPI usvfs::hooks::WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
  return WritePrivateProfileStringW(
    ush::string_cast<std::wstring>(lpAppName).c_str(),
    ush::string_cast<std::wstring>(lpKeyName).c_str(),
    ush::string_cast<std::wstring>(lpString).c_str(),
    ush::string_cast<std::wstring>(lpFileName).c_str()
  );
}

BOOL WINAPI usvfs::hooks::WritePrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  BOOL res = false;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

    if (!callContext.active()) {
      return ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, lpFileName);
    }

  bool create = false;

  RerouteW reroute;
  {
    auto context = READ_CONTEXT();
    reroute = RerouteW::create(context, callContext, lpFileName);
    if (!reroute.wasRerouted() && !fileExists(lpFileName)) {
      // the file will be created so now we need to know where
      reroute = RerouteW::createNew(context, callContext, lpFileName);
      create = (reroute.wasRerouted());

      if (create) {
        fs::path target(reroute.fileName());
        winapi::ex::wide::createPath(target.parent_path().wstring().c_str());
      }
    }
  }

  PRE_REALCALL
    res = ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, reroute.fileName());
  POST_REALCALL


    if (create && (res != FALSE)) {
      spdlog::get("hooks")
        ->info("add file to vfs: {}",
          ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8));
      // new file was created in a mapped directory, insert to vitual structure
      reroute.insertMapping(WRITE_CONTEXT());
    }

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAM(lpKeyName)
      .PARAM(lpString)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(::GetLastError());
  }

  HOOK_END

  return res;
}

VOID WINAPI usvfs::hooks::ExitProcess(UINT exitCode)
{
  HOOK_START

  {
    HookContext::Ptr context = WRITE_CONTEXT();

    std::vector<std::future<int>> &delayed = context->delayed();

    if (!delayed.empty()) {
      // ensure all delayed tasks are completed before we exit the process
      for (std::future<int> &delayedOp : delayed) {
        delayedOp.get();
      }
      delayed.clear();
    }
  }

  // exitprocess doesn't return so logging the call after the real call doesn't
  // make much sense.
  // nor does any pre/post call macro
  LOG_CALL().PARAM(exitCode);

  DisconnectVFS();

  //  HookManager::instance().removeHook("ExitProcess");
  //  PRE_REALCALL
  ::ExitProcess(exitCode);
  //  POST_REALCALL

  HOOK_END
}
