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

static inline WCHAR pathNameDriveLetter(LPCWSTR path)
{
  if (!path || !path[0])
    return 0;
  if (path[1] == ':')
    return path[0];
  // if path is not ?: or \* then we need to get absolute path:
  std::wstring buf;
  if (path[0] != '\\') {
    buf = winapi::wide::getFullPathName(path).first;
    path = buf.c_str();
    if (!path[0] || path[1] == ':')
      return path[0];
  }
  // check for \??\C:
  if (path[1] && path[2] && path[3] && path[4] && path[0] == '\\' && path[3] == '\\' && path[5] == ':')
    return path[4];
  // give up
  return 0;
}

// returns false also in case we fail to determine the drive letter of the path
static inline bool pathesOnDifferentDrives(LPCWSTR path1, LPCWSTR path2)
{
  WCHAR drive1 = pathNameDriveLetter(path1);
  WCHAR drive2 = pathNameDriveLetter(path2);
  return drive1 && drive2 && towupper(drive1) != towupper(drive2);
}

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

  template <class char_t>
  static bool interestingPathImpl(const char_t *inPath)
  {
    if (!inPath || !inPath[0])
      return false;
    // ignore \\.\ unless its a \\.\?:
    if (inPath[0] == '\\' && inPath[1] == '\\' && inPath[2] == '.' && inPath[3] == '\\' && (!inPath[4] || inPath[5] != ':'))
      return false;
    // ignore L"hid#":
    if ((inPath[0] == 'h' || inPath[0] == 'H')
      && ((inPath[1] == 'i' || inPath[1] == 'I'))
      && ((inPath[2] == 'd' || inPath[2] == 'D'))
      && inPath[3] == '#')
      return false;
    return true;
  }

  static bool interestingPath(const char* inPath) { return interestingPathImpl(inPath); }
  static bool interestingPath(const wchar_t* inPath) { return interestingPathImpl(inPath); }

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
                            LPCWSTR inPath, bool createPath = true,
                            LPSECURITY_ATTRIBUTES securityAttributes = nullptr)
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
        if (createPath)
          try {
            usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::ALL_GROUPS);
            winapi::ex::wide::createPath(fs::path(result.m_Buffer).parent_path(), securityAttributes);
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

  static RerouteW noReroute(LPCWSTR inPath)
  {
    RerouteW result;
    if ((inPath != nullptr) && (inPath[0] != L'\0')
      && !ush::startswith(inPath, L"hid#")) {
      result.m_Buffer = std::wstring(inPath);
      result.m_Rerouted = false;
      std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
      result.m_FileName = result.m_Buffer.c_str();
    }
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

HMODULE WINAPI usvfs::hook_LoadLibraryExW(LPCWSTR lpFileName, HANDLE hFile,
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

BOOL(WINAPI *usvfs::CreateProcessInternalW)(LPVOID token, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, LPVOID newToken);

BOOL WINAPI usvfs::hook_CreateProcessInternalW(
    LPVOID token,
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation,
    LPVOID newToken)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)
  if (!callContext.active()) {
    res = CreateProcessInternalW(
        token,
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation,
        newToken);
    callContext.updateLastError();
    return res;
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
  res = CreateProcessInternalW(
      token,
      applicationReroute.fileName(),
      lpCommandLine != nullptr ? &cmdline[0] : nullptr, lpProcessAttributes,
      lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
      lpCurrentDirectory, lpStartupInfo, lpProcessInformation,
      newToken);
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

// returns true iff the path exists (checks only real paths)
static inline bool pathExists(LPCWSTR fileName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES;
}

// returns true iff the path exists and is a file (checks only real paths)
static inline bool pathIsFile(LPCWSTR fileName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// returns true iff the path exists and is a file (checks only real paths)
static inline bool pathIsDirectory(LPCWSTR fileName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY);
}

// returns true iff the path does not exist but it parent directory does (checks only real paths)
static inline bool pathDirectlyAvailable(LPCWSTR pathName)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(pathName);
  return attrib == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
}

// attempts to copy source to destination and return the error code
static inline DWORD copyFileDirect(LPCWSTR source, LPCWSTR destination, bool overwrite)
{
  usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::SHELL_FILEOP);
  return
    CopyFileExW(source, destination, NULL, NULL, NULL, overwrite ? 0 : COPY_FILE_FAIL_IF_EXISTS) ?
    ERROR_SUCCESS : GetLastError();
}

HANDLE WINAPI usvfs::hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)
    if (callContext.active()) {
      HANDLE res = CreateFileW(
        ush::string_cast<std::wstring>(lpFileName).c_str(), dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
      callContext.updateLastError();
      return res;
    }
  HOOK_END

  return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
      lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

namespace usvfs {
  class CreateRerouter {
  public:

    bool rereoute(const usvfs::HookContext::ConstPtr &context, const usvfs::HookCallContext &callContext,
      LPCWSTR lpFileName, DWORD& dwCreationDisposition, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
      enum class Open { existing, create, empty, readWrite, speculativeWrite };
      Open open = Open::existing;

      // Notice since we are calling our patched GetFileAttributesW here this will also check virtualized paths
      DWORD virtAttr = GetFileAttributesW(lpFileName);
      bool directlyAvailable = virtAttr == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
      bool isFile = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
      m_isDir = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY);

      if (!m_isDir) {
        bool readAccess = dwDesiredAccess & (GENERIC_ALL | GENERIC_READ | FILE_READ_DATA);
        bool writeAccess = dwDesiredAccess & (GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA);

        switch (dwCreationDisposition) {
        case CREATE_ALWAYS:
          open = Open::create;
          if (isFile)
            m_error_on_success = ERROR_ALREADY_EXISTS;
          break;

        case CREATE_NEW:
          if (isFile) {
            m_error = ERROR_FILE_EXISTS;
            return false;
          }
          else
            open = Open::create;
          break;

        case OPEN_ALWAYS:
          if (isFile) {
            m_error_on_success = ERROR_ALREADY_EXISTS;
            if (writeAccess)
              if (readAccess)
                open = Open::readWrite;
              else
                open = Open::speculativeWrite;
          }
          else
            open = Open::create;
          break;

        case OPEN_EXISTING:
          if (isFile && writeAccess)
            if (readAccess)
              open = Open::readWrite;
            else
              open = Open::speculativeWrite;
          // if !isFile we let the OS create function set the error value
          break;

        case TRUNCATE_EXISTING:
          if ((dwDesiredAccess & GENERIC_WRITE) == 0) {
            m_error = ERROR_INVALID_PARAMETER;
            return false;
          }
          if (isFile)
            open = Open::empty;
          // if !isFile we let the OS create function set the error value
          break;
        }

        if (open == Open::create || open == Open::empty || open == Open::speculativeWrite)
        {
          bool createPath = open == Open::speculativeWrite || directlyAvailable || isFile;
          m_reroute = RerouteW::createNew(context, callContext, lpFileName, createPath, lpSecurityAttributes);
          // createNew may "fail" to reroute an existing file, for example if it exists only outside our writtable
          // locations (i.e. outside overwrite folder) even if there is a regular mapping for this file.
          // Therefore, fallback to the regular create in this case:
          bool createFallback = !m_reroute.wasRerouted();
          bool newFile = !createFallback && pathDirectlyAvailable(m_reroute.fileName());

          if (newFile && open == Open::empty)
            // TRUNCATE_EXISTING will fail since the new file doesn't exist, so change disposition:
            dwCreationDisposition = CREATE_ALWAYS;

          if (newFile && open == Open::speculativeWrite)
          {
            spdlog::get("hooks")->info(
              "file opened only for writing, activating copy-on-speculative-write: {}",
              ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8));

            RerouteW source = RerouteW::create(context, callContext, lpFileName);
            DWORD copyRes = copyFileDirect(source.fileName(), m_reroute.fileName(), false);
            if (copyRes != ERROR_SUCCESS)
            {
              spdlog::get("hooks")->info(
                "copy-on-speculative-write failed to copy: {} => {}",
                ush::string_cast<std::string>(source.fileName(), ush::CodePage::UTF8),
                ush::string_cast<std::string>(m_reroute.fileName(), ush::CodePage::UTF8));
              createFallback = true;
            }
          }

          if (!createFallback) {
            m_create = m_reroute.wasRerouted();
            return true;
          }
        }
      }

      if (m_isDir && pathIsDirectory(lpFileName))
        m_reroute = RerouteW::noReroute(lpFileName);
      else
        m_reroute = RerouteW::create(context, callContext, lpFileName);

      if (m_reroute.wasRerouted() && open == Open::readWrite)
        spdlog::get("hooks")->info(
          "file opened for both reading and writing, original file may be altered (copy-on-readwrite not supported): {}",
          ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8));

      return true;
    }

    DWORD fixErrorCode(bool success, DWORD error)
    {
      if (success && m_error_on_success != ERROR_SUCCESS)
        return m_error_on_success;
      return error;
    }

    DWORD error() const { return m_error; }
    bool isDir() const { return m_isDir; }
    bool create() const { return m_create; }
    bool wasRerouted() const { return m_reroute.wasRerouted(); }
    LPCWSTR fileName() const { return m_reroute.fileName(); }

    void insertMapping(const usvfs::HookContext::Ptr &context) { m_reroute.insertMapping(context); }

  private:
    DWORD m_error = ERROR_SUCCESS;
    DWORD m_error_on_success = ERROR_SUCCESS;
    bool m_isDir = false;
    bool m_create = false;
    RerouteW m_reroute;
  };
};

HANDLE WINAPI usvfs::hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
    res = ::CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
    callContext.updateLastError();
    return res;
  }

  DWORD originalDisposition = dwCreationDisposition;
  CreateRerouter rerouter;
  if (rerouter.rereoute(READ_CONTEXT(), callContext, lpFileName, dwCreationDisposition, dwDesiredAccess, lpSecurityAttributes))
  {
    PRE_REALCALL
      res = ::CreateFileW(rerouter.fileName(), dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
    POST_REALCALL
    DWORD originalError = callContext.lastError();
    DWORD fixedError = rerouter.fixErrorCode(res != INVALID_HANDLE_VALUE, originalError);
    if (fixedError != originalError)
      callContext.updateLastError(fixedError);

    if (res != INVALID_HANDLE_VALUE) {
      if (rerouter.create())
        rerouter.insertMapping(WRITE_CONTEXT());

      if (rerouter.isDir() && rerouter.wasRerouted() && (dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS))
      {
        // store the original search path for use during iteration
        WRITE_CONTEXT()
          ->customData<SearchHandleMap>(SearchHandles)[res]
          = lpFileName;
      }
    }

    if (rerouter.wasRerouted() || fixedError != originalError || originalDisposition != dwCreationDisposition) {
      LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(rerouter.fileName())
        .PARAMHEX(dwDesiredAccess)
        .PARAMHEX(originalDisposition)
        .PARAMHEX(dwCreationDisposition)
        .PARAMHEX(dwFlagsAndAttributes)
        .PARAMHEX(res)
        .PARAMHEX(originalError)
        .PARAMHEX(fixedError);
    }
  }
  else {
    spdlog::get("hooks")->info(
      "hook_CreateFileW guaranteed failure, skipping original call: {}, disposition={}, access={}, error={}",
      ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8),
      dwCreationDisposition, dwDesiredAccess, rerouter.error());

    callContext.updateLastError(rerouter.error());
  }

  HOOK_END

  return res;
}

HANDLE (WINAPI *usvfs::CreateFile2)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams);

HANDLE WINAPI usvfs::hook_CreateFile2(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  typedef HANDLE(WINAPI * CreateFile2_t)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
    HANDLE res = CreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
    callContext.updateLastError();
    return res;
  }

  DWORD originalDisposition = dwCreationDisposition;
  CreateRerouter rerouter;
  if (rerouter.rereoute(READ_CONTEXT(), callContext, lpFileName, dwCreationDisposition, dwDesiredAccess,
                        pCreateExParams ? pCreateExParams->lpSecurityAttributes : nullptr))
  {
    PRE_REALCALL
      res = CreateFile2(rerouter.fileName(), dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
    POST_REALCALL
    DWORD originalError = callContext.lastError();
    DWORD fixedError = rerouter.fixErrorCode(res != INVALID_HANDLE_VALUE, originalError);
    if (fixedError != originalError)
      callContext.updateLastError(fixedError);

    if (res != INVALID_HANDLE_VALUE) {
      if (rerouter.create())
        rerouter.insertMapping(WRITE_CONTEXT());

      if (rerouter.isDir() && rerouter.wasRerouted()
        && pCreateExParams && (pCreateExParams->dwFileFlags & FILE_FLAG_BACKUP_SEMANTICS))
      {
        // store the original search path for use during iteration
        WRITE_CONTEXT()
          ->customData<SearchHandleMap>(SearchHandles)[res]
          = lpFileName;
      }
    }

    if (rerouter.wasRerouted() || fixedError != originalError || originalDisposition != dwCreationDisposition) {
      LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(rerouter.fileName())
        .PARAMHEX(dwDesiredAccess)
        .PARAMHEX(originalDisposition)
        .PARAMHEX(dwCreationDisposition)
        .PARAMHEX(res)
        .PARAMHEX(originalError)
        .PARAMHEX(fixedError);
    }
  }
  else {
    spdlog::get("hooks")->info(
      "hook_CreateFileW guaranteed failure, skipping original call: {}, disposition={}, access={}, error={}",
      ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8),
      dwCreationDisposition, dwDesiredAccess, rerouter.error());

    callContext.updateLastError(rerouter.error());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_GetFileAttributesExW(
    LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)
  if (!callContext.active()) {
    res = GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res = ::GetFileAttributesExW(reroute.fileName(), fInfoLevelId,
                               lpFileInformation);
  POST_REALCALL

  DWORD originalError = callContext.lastError();
  DWORD fixedError = originalError;
  // In case the target does not exist the error value varies to differentiate if the
  // parent folder exists (ERROR_FILE_NOT_FOUND) or not (ERROR_PATH_NOT_FOUND).
  // If the original target's parent folder doesn't actually exist it may exist in the
  // the virtualized sense, or if we rerouted the query the parent of the original path
  // might exist while the parent of the rerouted path might not:
  if (!res && fixedError == ERROR_PATH_NOT_FOUND)
  {
    // first query original file parent (if we rerouted it):
    fs::path originalParent = fs::path(lpFileName).parent_path();
    WIN32_FILE_ATTRIBUTE_DATA parentAttr;
    if (reroute.wasRerouted()
      && ::GetFileAttributesExW(originalParent.c_str(), GetFileExInfoStandard, &parentAttr)
      && (parentAttr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      fixedError = ERROR_FILE_NOT_FOUND;
    else {
      // now query the rerouted path for parent (which can be different from the parent of the rerouted path)
      RerouteW rerouteParent = RerouteW::create(READ_CONTEXT(), callContext, originalParent.c_str());
      if (rerouteParent.wasRerouted()
        && ::GetFileAttributesExW(rerouteParent.fileName(), GetFileExInfoStandard, &parentAttr)
        && (parentAttr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        fixedError = ERROR_FILE_NOT_FOUND;
    }
  }
  if (fixedError != originalError)
    callContext.updateLastError(fixedError);

  if (reroute.wasRerouted() || fixedError != originalError) {
    DWORD resAttrib;
    if (res && fInfoLevelId == GetFileExInfoStandard && lpFileInformation)
      resAttrib = reinterpret_cast<WIN32_FILE_ATTRIBUTE_DATA*>(lpFileInformation)->dwFileAttributes;
    else
      resAttrib = (DWORD)-1;
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(fInfoLevelId)
        .PARAMHEX(res)
        .PARAMHEX(resAttrib)
        .PARAMHEX(originalError)
        .PARAMHEX(fixedError);
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetFileAttributesW(LPCWSTR lpFileName)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)
  if (!callContext.active()) {
    res = GetFileAttributesW(lpFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res = ::GetFileAttributesW(reroute.fileName());
  POST_REALCALL

  DWORD originalError = callContext.lastError();
  DWORD fixedError = originalError;
  // In case the target does not exist the error value varies to differentiate if the
  // parent folder exists (ERROR_FILE_NOT_FOUND) or not (ERROR_PATH_NOT_FOUND).
  // If the original target's parent folder doesn't actually exist it may exist in the
  // the virtualized sense, or if we rerouted the query the parent of the original path
  // might exist while the parent of the rerouted path might not:
  if (res == INVALID_FILE_ATTRIBUTES && fixedError == ERROR_PATH_NOT_FOUND)
  {
    // first query original file parent (if we rerouted it):
    fs::path originalParent = fs::path(lpFileName).parent_path();
    DWORD attr;
    if (reroute.wasRerouted()
      && (attr = ::GetFileAttributesW(originalParent.c_str())) != INVALID_FILE_ATTRIBUTES
      && (attr & FILE_ATTRIBUTE_DIRECTORY))
      fixedError = ERROR_FILE_NOT_FOUND;
    else {
      // now query the rerouted path for parent (which can be different from the parent of the rerouted path)
      RerouteW rerouteParent = RerouteW::create(READ_CONTEXT(), callContext, originalParent.c_str());
      if (rerouteParent.wasRerouted()
        && (attr = ::GetFileAttributesW(rerouteParent.fileName())) != INVALID_FILE_ATTRIBUTES
        && (attr & FILE_ATTRIBUTE_DIRECTORY))
        fixedError = ERROR_FILE_NOT_FOUND;
    }
  }
  if (fixedError != originalError)
    callContext.updateLastError(fixedError);

  if (reroute.wasRerouted() || fixedError != originalError) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAMHEX(originalError)
        .PARAMHEX(fixedError);
  }

  HOOK_ENDP(usvfs::log::wrap(lpFileName));

  return res;
}

DWORD WINAPI usvfs::hook_SetFileAttributesW(
	LPCWSTR lpFileName, DWORD dwFileAttributes)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)
  if (!callContext.active()) {
    res = SetFileAttributesW(lpFileName, dwFileAttributes);
    callContext.updateLastError();
    return res;
  }

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

BOOL WINAPI usvfs::hook_DeleteFileW(LPCWSTR lpFileName)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::DELETE_FILE)
  if (!callContext.active()) {
    res = DeleteFileW(lpFileName);
    callContext.updateLastError();
    return res;
  }

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

void updateMoveFileFlags(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
  const RerouteW& readReroute, const RerouteW& writeReroute, DWORD& newFlags)
{
  // if original source and destination were on the same drive but after the reroute
  // they are on different drives, the move would have succeed before but will now fail
  // unless MOVEFILE_COPY_ALLOWED is specified, so force this flag in this case:
  if ((newFlags & MOVEFILE_COPY_ALLOWED) == 0 && (readReroute.wasRerouted() || writeReroute.wasRerouted())
    && pathesOnDifferentDrives(readReroute.fileName(), writeReroute.fileName())
    && !pathesOnDifferentDrives(lpExistingFileName, lpNewFileName))
    newFlags |= MOVEFILE_COPY_ALLOWED;
}

BOOL WINAPI usvfs::hook_MoveFileA(LPCSTR lpExistingFileName,
                                    LPCSTR lpNewFileName)
{
  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
    if (callContext.active()) {
      BOOL res = MoveFileW(
        ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
        ush::string_cast<std::wstring>(lpNewFileName).c_str());
      callContext.updateLastError();
      return res;
    }
  HOOK_END

  return MoveFileA(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI usvfs::hook_MoveFileW(LPCWSTR lpExistingFileName,
                                    LPCWSTR lpNewFileName)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  if (!callContext.active()) {
    res = MoveFileW(lpExistingFileName, lpNewFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW readReroute;
  RerouteW writeReroute;
  DWORD newFlags = 0;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  if (newFlags)
    res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
  else
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
        .PARAMWRAP(newFlags)
        .PARAM(res)
        .PARAM(callContext.lastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_MoveFileExA(LPCSTR lpExistingFileName,
                                      LPCSTR lpNewFileName, DWORD dwFlags)
{
  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
    if (callContext.active()) {
      BOOL res = MoveFileExW(ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
        ush::string_cast<std::wstring>(lpNewFileName).c_str(),
        dwFlags);
      callContext.updateLastError();
      return res;
    }
  HOOK_END

  return MoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
}

BOOL WINAPI usvfs::hook_MoveFileExW(LPCWSTR lpExistingFileName,
                                      LPCWSTR lpNewFileName, DWORD dwFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  if (!callContext.active()) {
    res = MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
    callContext.updateLastError();
    return res;
  }

  RerouteW readReroute;
  RerouteW writeReroute;
  DWORD newFlags = dwFlags;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
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
        .PARAMWRAP(dwFlags)
        .PARAMWRAP(newFlags)
        .PARAM(res)
        .PARAM(callContext.lastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_MoveFileWithProgressA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, DWORD dwFlags)
{
  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
    if (callContext.active()) {
      BOOL res = MoveFileWithProgressW(
        ush::string_cast<std::wstring>(lpExistingFileName).c_str(),
        ush::string_cast<std::wstring>(lpNewFileName).c_str(),
        lpProgressRoutine, lpData, dwFlags);
      callContext.updateLastError();
      return res;
    }
  HOOK_END

  return MoveFileWithProgressA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags);
}

BOOL WINAPI usvfs::hook_MoveFileWithProgressW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, DWORD dwFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  if (!callContext.active()) {
    res = MoveFileWithProgressW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags);
    callContext.updateLastError();
    return res;
  }

  RerouteW readReroute;
  RerouteW writeReroute;
  DWORD newFlags = dwFlags;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  res = ::MoveFileWithProgressW(readReroute.fileName(), writeReroute.fileName(), lpProgressRoutine, lpData, newFlags);
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
        .PARAMWRAP(dwFlags)
        .PARAMWRAP(newFlags)
        .PARAM(res)
        .PARAM(callContext.lastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_CopyFileExW(LPCWSTR lpExistingFileName,
                                      LPCWSTR lpNewFileName,
                                      LPPROGRESS_ROUTINE lpProgressRoutine,
                                      LPVOID lpData, LPBOOL pbCancel,
                                      DWORD dwCopyFlags)
{
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  if (!callContext.active()) {
    res = CopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    callContext.updateLastError();
    return res;
  }

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
        .PARAM(callContext.lastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetCurrentDirectoryA(DWORD nBufferLength,
                                                LPSTR lpBuffer)
{
  DWORD res = 0;

  HOOK_START

  std::wstring buffer;
  buffer.resize(nBufferLength);

  PRE_REALCALL
  res = GetCurrentDirectoryW(nBufferLength, &buffer[0]);
  POST_REALCALL

  if (res > 0) {
      res = WideCharToMultiByte(CP_ACP, 0, buffer.c_str(), res+1,
                                lpBuffer, nBufferLength, nullptr, nullptr);
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetCurrentDirectoryW(DWORD nBufferLength,
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

BOOL WINAPI usvfs::hook_SetCurrentDirectoryA(LPCSTR lpPathName) {
  return SetCurrentDirectoryW(
      ush::string_cast<std::wstring>(lpPathName).c_str());
}

BOOL WINAPI usvfs::hook_SetCurrentDirectoryW(LPCWSTR lpPathName)
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


DLLEXPORT BOOL WINAPI usvfs::hook_CreateDirectoryW(
    LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  BOOL res = FALSE;
  HOOK_START

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpPathName);
  bool create = reroute.fileName() && !pathExists(reroute.fileName());
  if (create)
    reroute = RerouteW::createNew(READ_CONTEXT(), callContext, lpPathName);

  PRE_REALCALL
  res = ::CreateDirectoryW(reroute.fileName(), lpSecurityAttributes);
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res);
  }
  HOOK_END

  return res;
}

DLLEXPORT BOOL WINAPI usvfs::hook_RemoveDirectoryW(
	LPCWSTR lpPathName)
{

	BOOL res = FALSE;

	HOOK_START_GROUP(MutExHookGroup::DELETE_FILE)
    if (!callContext.active()) {
      res = RemoveDirectoryW(lpPathName);
      callContext.updateLastError();
      return res;
    }

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

DWORD WINAPI usvfs::hook_GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FULL_PATHNAME)
  if (!callContext.active()) {
    res = GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, lpFilePart);
    callContext.updateLastError();
    return res;
  }

  auto context = READ_CONTEXT();

  std::wstring actualCWD = context->customData<std::wstring>(ActualCWD);
  std::string temp;
  if (actualCWD.empty() || fs::path(lpFileName).is_absolute()) {
    temp = lpFileName;
  }
  else {
    temp = ush::string_cast<std::string>((fs::path(actualCWD) / lpFileName).wstring());
  }
  PRE_REALCALL
    res = ::GetFullPathNameA(temp.c_str(), nBufferLength, lpBuffer, lpFilePart);
  POST_REALCALL

    if (false) {
      LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(lpBuffer)
        .PARAM(res)
        .PARAM(callContext.lastError());
    }

  // nothing to do here? Maybe if current directory is virtualised
  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetFullPathNameW(LPCWSTR lpFileName,
                                            DWORD nBufferLength,
                                            LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::FULL_PATHNAME)
  if (!callContext.active()) {
    res = GetFullPathNameW(lpFileName, nBufferLength, lpBuffer, lpFilePart);
    callContext.updateLastError();
    return res;
  }

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

  if (false) {
    LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(lpBuffer)
        .PARAM(res)
        .PARAM(callContext.lastError());
  }

  // nothing to do here? Maybe if current directory is virtualised
  HOOK_END

  return res;
}


DWORD WINAPI usvfs::hook_GetModuleFileNameW(HMODULE hModule,
                                              LPWSTR lpFilename, DWORD nSize)
{
  DWORD res = 0UL;

  HOOK_START_GROUP(MutExHookGroup::ALL_GROUPS)
  if (!callContext.active()) {
    res = GetModuleFileNameW(hModule, lpFilename, nSize);
    callContext.updateLastError();
    return res;
  }


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
          .PARAMHEX(callContext.lastError())
          .PARAM(res);
    }
  }
  HOOK_END

  return res;
}

HANDLE WINAPI usvfs::hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  HOOK_START_GROUP(MutExHookGroup::SEARCH_FILES)
  if (!callContext.active()) {
    res = FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    callContext.updateLastError();
    return res;
  }

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

HRESULT(WINAPI *usvfs::CopyFile2)(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters);

HRESULT WINAPI usvfs::hook_CopyFile2(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters)
{
  HRESULT res = E_FAIL;

  typedef HRESULT(WINAPI * CopyFile2_t)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS *);

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)
  if (!callContext.active()) {
    res = CopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
    callContext.updateLastError();
    return res;
  }

  RerouteW readReroute;
  RerouteW writeReroute;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, pwszExistingFileName);
    writeReroute = RerouteW::createNew(context, callContext, pwszNewFileName);
  }

	PRE_REALCALL
    if (!readReroute.wasRerouted() && !writeReroute.wasRerouted()) {
        res = CopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
    }
    else {
        res = CopyFile2(readReroute.fileName(), writeReroute.fileName(), pExtendedParameters);
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
      .PARAM(callContext.lastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetPrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, ush::string_cast<std::wstring>(lpFileName).c_str());

  PRE_REALCALL
  res =
    ::GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAM(lpKeyName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetPrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::GetPrivateProfileStringW(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res =
    ::GetPrivateProfileStringW(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, reroute.fileName());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAM(lpKeyName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetPrivateProfileSectionA(LPCSTR lpAppName, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::GetPrivateProfileSectionA(lpAppName, lpReturnedString, nSize, lpFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, ush::string_cast<std::wstring>(lpFileName).c_str());

  PRE_REALCALL
  res =
    ::GetPrivateProfileSectionA(lpAppName, lpReturnedString, nSize, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

DWORD WINAPI usvfs::hook_GetPrivateProfileSectionW(LPCWSTR lpAppName, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  DWORD res = 0;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::GetPrivateProfileSectionW(lpAppName, lpReturnedString, nSize, lpFileName);
    callContext.updateLastError();
    return res;
  }

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res =
    ::GetPrivateProfileSectionW(lpAppName, lpReturnedString, nSize, reroute.fileName());
  POST_REALCALL

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
  BOOL res = false;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, lpFileName);
    callContext.updateLastError();
    return res;
  }

  bool create = false;

  RerouteW reroute;
  {
    std::wstring fileName = ush::string_cast<std::wstring>(lpFileName);
    auto context = READ_CONTEXT();
    reroute = RerouteW::create(context, callContext, fileName.c_str());
    if (!reroute.wasRerouted() && !pathExists(fileName.c_str())) {
      // the file will be created so now we need to know where
      reroute = RerouteW::createNew(context, callContext, fileName.c_str());
      create = reroute.wasRerouted();
    }
  }

  PRE_REALCALL
  res =
    ::WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

  if (create && (res != FALSE))
    reroute.insertMapping(WRITE_CONTEXT());

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAM(lpKeyName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

BOOL WINAPI usvfs::hook_WritePrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  BOOL res = false;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active() || !lpFileName) {
    res = ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, lpFileName);
    callContext.updateLastError();
    return res;
  }

  bool create = false;

  RerouteW reroute;
  {
    auto context = READ_CONTEXT();
    reroute = RerouteW::create(context, callContext, lpFileName);
    if (!reroute.wasRerouted() && !pathExists(lpFileName)) {
      // the file will be created so now we need to know where
      reroute = RerouteW::createNew(context, callContext, lpFileName);
      create = reroute.wasRerouted();
    }
  }

  PRE_REALCALL
  res =
    ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, reroute.fileName());
  POST_REALCALL

  if (create && (res != FALSE))
    reroute.insertMapping(WRITE_CONTEXT());

  if (reroute.wasRerouted()) {
    LOG_CALL()
      .PARAM(lpAppName)
      .PARAM(lpKeyName)
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(reroute.fileName())
      .PARAMHEX(res)
      .PARAMHEX(callContext.lastError());
  }

  HOOK_END

  return res;
}

VOID WINAPI usvfs::hook_ExitProcess(UINT exitCode)
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
