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
#include <mutex>
#include <shared_mutex>

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

class DeleteTracker {
public:
  using wstring = std::wstring;

  wstring lookup(const wstring& deletePath) const {
    if (!deletePath.empty())
    {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(deletePath);
      if (find != m_map.end())
        return find->second;
    }
    return wstring();
  }

  void insert(const wstring& deletePath, const wstring& realPath) {
    if (deletePath.empty())
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map[deletePath] = realPath;
  }

  void erase(const wstring& deletePath)
  {
    if (deletePath.empty())
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map.erase(deletePath);
  }

private:
  mutable std::shared_mutex m_mutex;
  std::unordered_map<wstring, wstring> m_map;
};

DeleteTracker k32DeleteTracker;

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
  bool m_PathCreated{false};
  bool m_NewReroute{false};

  usvfs::RedirectionTree::NodePtrT m_FileNode;

public:
  RerouteW() = default;

  RerouteW(RerouteW &&reference)
    : m_Buffer(std::move(reference.m_Buffer))
    , m_RealPath(std::move(reference.m_RealPath))
    , m_Rerouted(reference.m_Rerouted)
    , m_PathCreated(reference.m_PathCreated)
    , m_NewReroute(reference.m_NewReroute)
    , m_FileNode(std::move(reference.m_FileNode))
  {
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
    reference.m_FileName = nullptr;
  }

  RerouteW &operator=(RerouteW &&reference)
  {
    m_Buffer   = std::move(reference.m_Buffer);
    m_RealPath = std::move(reference.m_RealPath);
    m_Rerouted = reference.m_Rerouted;
    m_PathCreated = reference.m_PathCreated;
    m_NewReroute = reference.m_NewReroute;
    m_FileName = reference.m_FileName != nullptr ? m_Buffer.c_str() : nullptr;
    m_FileNode = std::move(reference.m_FileNode);
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

  bool newReroute() const
  {
    return m_NewReroute;
  }

  void insertMapping(const usvfs::HookContext::Ptr &context, bool directory = false)
  {
    if (directory)
      addDirectoryMapping(context, m_RealPath, m_FileName);
    else
    {
      if (m_PathCreated)
        addDirectoryMapping(context, fs::path(m_RealPath).parent_path(), fs::path(m_FileName).parent_path());

      spdlog::get("hooks")->info("mapping file in vfs: {}, {}",
        ush::string_cast<std::string>(m_RealPath, ush::CodePage::UTF8),
        ush::string_cast<std::string>(m_FileName, ush::CodePage::UTF8));
      m_FileNode =
        context->redirectionTable().addFile(m_RealPath, usvfs::RedirectionDataLocal(string_cast<std::string>(m_FileName, CodePage::UTF8)));

      k32DeleteTracker.erase(m_RealPath);
    }
  }

  void removeMapping(bool directory = false)
  {
    if (!directory)
      k32DeleteTracker.insert(m_RealPath, m_FileName);

    if (wasRerouted())
      if (m_FileNode.get())
        m_FileNode->removeFromTree();
      else
        spdlog::get("usvfs")->warn("Node not removed: {}", string_cast<std::string>(m_FileName));
  }

  static bool addDirectoryMapping(const usvfs::HookContext::Ptr &context, const fs::path& originalPath, const fs::path& reroutedPath)
  {
    if (originalPath.empty() || reroutedPath.empty()) {
      spdlog::get("hooks")->error("RerouteW::addDirectoryMapping failed: {}, {}",
        string_cast<std::string>(originalPath.wstring(), CodePage::UTF8).c_str(),
        string_cast<std::string>(reroutedPath.wstring(), CodePage::UTF8).c_str());
      return false;
    }

    auto lookupParent = context->redirectionTable()->findNode(originalPath.parent_path());
    if (!lookupParent.get() || lookupParent->data().linkTarget.empty()) {
      if (!addDirectoryMapping(context, originalPath.parent_path(), reroutedPath.parent_path()))
      {
        spdlog::get("hooks")->error("RerouteW::addDirectoryMapping failed: {}, {}",
          string_cast<std::string>(originalPath.wstring(), CodePage::UTF8).c_str(),
          string_cast<std::string>(reroutedPath.wstring(), CodePage::UTF8).c_str());
        return false;
      }
    }

    std::string reroutedU8
      = ush::string_cast<std::string>(reroutedPath.wstring(), ush::CodePage::UTF8);
    if (reroutedU8.empty() || reroutedU8[reroutedU8.size() - 1] != '\\')
      reroutedU8 += "\\";

    spdlog::get("hooks")->info("mapping directory in vfs: {}, {}",
      ush::string_cast<std::string>(originalPath.wstring(), ush::CodePage::UTF8), reroutedU8.c_str());

    context->redirectionTable().addDirectory(
      originalPath, usvfs::RedirectionDataLocal(reroutedU8),
      usvfs::shared::FLAG_DIRECTORY|usvfs::shared::FLAG_CREATETARGET);

    return true;
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

  static fs::path absolutePath(const wchar_t *inPath)
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

  static fs::path canonizePath(const fs::path& inPath)
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

    if (interestingPath(inPath) && callContext.active())
    {
      const auto& lookupPath = canonizePath(absolutePath(inPath));
      result.m_RealPath = lookupPath.wstring();

      const usvfs::RedirectionTreeContainer &table
        = inverse ? context->inverseTable() : context->redirectionTable();
      result.m_FileNode = table->findNode(lookupPath);

      if (result.m_FileNode.get()
        && (!result.m_FileNode->data().linkTarget.empty() || result.m_FileNode->isDirectory()))
      {
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
        std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
        result.m_Rerouted = true;
      }
      else
        result.m_Buffer = inPath;
    }
    else if (inPath)
      result.m_Buffer = inPath;

    if (inPath)
      result.m_FileName = result.m_Buffer.c_str();
    return result;
  }

  static RerouteW createNew(const usvfs::HookContext::ConstPtr &context,
                            const usvfs::HookCallContext &callContext,
                            LPCWSTR inPath, bool createPath = true,
                            LPSECURITY_ATTRIBUTES securityAttributes = nullptr)
  {
    RerouteW result;

    if (interestingPath(inPath) && callContext.active())
    {
      const auto& lookupPath = canonizePath(absolutePath(inPath));
      result.m_RealPath = lookupPath.wstring();

      result.m_Buffer = k32DeleteTracker.lookup(result.m_RealPath);
      bool found = !result.m_Buffer.empty();
      if (found)
        spdlog::get("hooks")->info("Rerouting file creation to original location of deleted file: {}",
          ush::string_cast<std::string>(result.m_Buffer));
      else
      {
        FindCreateTarget visitor;
        usvfs::RedirectionTree::VisitorFunction visitorWrapper =
          [&](const usvfs::RedirectionTree::NodePtrT &node) { visitor(node); };
        context->redirectionTable()->visitPath(lookupPath, visitorWrapper);
        if (visitor.target.get()) {
          // the visitor has found the last (deepest in the directory hierarchy)
          // create-target
          fs::path relativePath
            = ush::make_relative(visitor.target->path(), lookupPath);
          result.m_Buffer =
            (fs::path(visitor.target->data().linkTarget.c_str()) / relativePath).wstring();
          found = true;
        }
      }

      if (found)
      {
        if (createPath)
          try {
            usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::ALL_GROUPS);
            result.m_PathCreated =
              winapi::ex::wide::createPath(fs::path(result.m_Buffer).parent_path(), securityAttributes);
          } catch (const std::exception &e) {
            spdlog::get("hooks")->error("failed to create {}: {}",
              ush::string_cast<std::string>(result.m_Buffer), e.what());
          }

        std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
        result.m_Rerouted = true;
        result.m_NewReroute = true;
      }
      else
        result.m_Buffer = inPath;
    }
    else if (inPath)
      result.m_Buffer = inPath;

    if (inPath)
      result.m_FileName = result.m_Buffer.c_str();
    return result;
  }

  static RerouteW createOrNew(const usvfs::HookContext::ConstPtr &context, const usvfs::HookCallContext &callContext,
                              LPCWSTR inPath, bool createPath = true, LPSECURITY_ATTRIBUTES securityAttributes = nullptr)
  {
    {
      auto res = create(context, callContext, inPath);
      if (res.wasRerouted() || !interestingPath(inPath) || !callContext.active() || pathExists(inPath))
        return std::move(res);
    }
    return createNew(context, callContext, inPath, createPath, securityAttributes);
  }

  static RerouteW noReroute(LPCWSTR inPath)
  {
    RerouteW result;
    if (inPath)
      result.m_Buffer = inPath;
    if (inPath && inPath[0] && !ush::startswith(inPath, L"hid#"))
      std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
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

    if (RerouteW::interestingPath(lpCommandLine)) {
      // decompose command line
      int argc = 0;
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
    else if (lpCommandLine)
      cmdline = lpCommandLine;

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

  if (res)
  {
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

    // resume unless process is suposed to start suspended
    if (!susp && (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
      spdlog::get("hooks")->error("failed to inject into spawned process");
      res = FALSE;
    }
  }

  LOG_CALL()
      .PARAM(lpApplicationName)
      .PARAM(applicationReroute.fileName())
      .PARAM(cmdline)
      .PARAM(res);

  HOOK_END

  return res;
}

HANDLE WINAPI usvfs::hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
  HANDLE res = INVALID_HANDLE_VALUE;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  if (!callContext.active()) {
    res = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
      lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    callContext.updateLastError();
    return res;
  }

  // release the MutExHookGroup::OPEN_FILE so that CreateFileW can process the request:
  HOOK_END
  HOOK_START

  const auto& fileName = ush::string_cast<std::wstring>(lpFileName);

  PRE_REALCALL
    res = CreateFileW(fileName.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
      dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
  POST_REALCALL

  HOOK_END

  return res;
}

namespace usvfs {
  class CreateRerouter {
  public:

    bool rereoute(const usvfs::HookContext::ConstPtr &context, const usvfs::HookCallContext &callContext,
      LPCWSTR lpFileName, DWORD& dwCreationDisposition, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
      enum class Open { existing, create, empty };
      Open open = Open::existing;

      // Notice since we are calling our patched GetFileAttributesW here this will also check virtualized paths
      DWORD virtAttr = GetFileAttributesW(lpFileName);
      m_directlyAvailable = virtAttr == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
      bool isFile = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
      m_isDir = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY);

      if (!m_isDir)
      {
        switch (dwCreationDisposition) {
        case CREATE_ALWAYS:
          open = Open::create;
          if (isFile)
            m_error = ERROR_ALREADY_EXISTS;
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
          if (isFile)
            m_error = ERROR_ALREADY_EXISTS;
          else
            open = Open::create;
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
      }

      if (m_isDir && pathIsDirectory(lpFileName))
        m_reroute = RerouteW::noReroute(lpFileName);
      else
        m_reroute = RerouteW::create(context, callContext, lpFileName);

      if (!m_isDir && !isFile && !m_reroute.wasRerouted() && (open == Open::create || open == Open::empty))
      {
        m_reroute = RerouteW::createNew(context, callContext, lpFileName, m_directlyAvailable, lpSecurityAttributes);

        bool newFile = !m_reroute.wasRerouted() && pathDirectlyAvailable(m_reroute.fileName());
        if (newFile && open == Open::empty)
          // TRUNCATE_EXISTING will fail since the new file doesn't exist, so change disposition:
          dwCreationDisposition = CREATE_ALWAYS;

        m_create = m_reroute.wasRerouted();
      }

      return true;
    }

    void updateResult(usvfs::HookCallContext &callContext, bool success)
    {
      m_originalError = callContext.lastError();
      if (success) {
        // m_error != ERROR_SUCCESS means we are overriding the error on success
        if (m_error == ERROR_SUCCESS)
          m_error = m_originalError;
      }
      else if (m_originalError == ERROR_PATH_NOT_FOUND && m_directlyAvailable)
        m_error = ERROR_FILE_NOT_FOUND;
      else
        m_error = m_originalError;
      if (m_error != m_originalError)
        callContext.updateLastError(m_error);
    }

    DWORD error() const { return m_error; }
    DWORD originalError() const { return m_originalError; }
    bool changedError() const { return m_error != m_originalError; }

    bool isDir() const { return m_isDir; }
    bool create() const { return m_create; }
    bool wasRerouted() const { return m_reroute.wasRerouted(); }
    LPCWSTR fileName() const { return m_reroute.fileName(); }

    void insertMapping(const usvfs::HookContext::Ptr &context) { m_reroute.insertMapping(context); }

  private:
    DWORD m_error = ERROR_SUCCESS;
    DWORD m_originalError = ERROR_SUCCESS;
    bool m_directlyAvailable = false;
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
    rerouter.updateResult(callContext, res != INVALID_HANDLE_VALUE);

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

    if (rerouter.wasRerouted() || rerouter.changedError() || originalDisposition != dwCreationDisposition) {
      LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(rerouter.fileName())
        .PARAMHEX(dwDesiredAccess)
        .PARAMHEX(originalDisposition)
        .PARAMHEX(dwCreationDisposition)
        .PARAMHEX(dwFlagsAndAttributes)
        .PARAMHEX(res)
        .PARAMHEX(rerouter.originalError())
        .PARAMHEX(rerouter.error());
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
    rerouter.updateResult(callContext, res != INVALID_HANDLE_VALUE);

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

    if (rerouter.wasRerouted() || rerouter.changedError() || originalDisposition != dwCreationDisposition) {
      LOG_CALL()
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(rerouter.fileName())
        .PARAMHEX(dwDesiredAccess)
        .PARAMHEX(originalDisposition)
        .PARAMHEX(dwCreationDisposition)
        .PARAMHEX(res)
        .PARAMHEX(rerouter.originalError())
        .PARAMHEX(rerouter.error());
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
  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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
  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  if (reroute.wasRerouted()) {
    res = ::DeleteFileW(reroute.fileName());
  } else {
    res = ::DeleteFileW(lpFileName);
  }
  POST_REALCALL

  reroute.removeMapping();
  if (reroute.wasRerouted())
    LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(reroute.fileName()).PARAM(res);

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
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  if (!callContext.active()) {
    res = MoveFileA(lpExistingFileName, lpNewFileName);
    callContext.updateLastError();
    return res;
  }

  HOOK_END
  HOOK_START

  const auto& existingFileName = ush::string_cast<std::wstring>(lpExistingFileName);
  const auto& newFileName = ush::string_cast<std::wstring>(lpNewFileName);

  PRE_REALCALL
    res = MoveFileW(existingFileName.c_str(), newFileName.c_str());
  POST_REALCALL

  HOOK_END

  return res;
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
    writeReroute = RerouteW::createOrNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  if (newFlags)
    res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
  else
    res = ::MoveFileW(readReroute.fileName(), writeReroute.fileName());
  POST_REALCALL

  if (res) {
    readReroute.removeMapping();

    if (writeReroute.newReroute()) {
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
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  if (!callContext.active()) {
    res = MoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
    callContext.updateLastError();
    return res;
  }

  HOOK_END
  HOOK_START

  const auto& existingFileName = ush::string_cast<std::wstring>(lpExistingFileName);
  const auto& newFileName = ush::string_cast<std::wstring>(lpNewFileName);

  PRE_REALCALL
    res = MoveFileExW(existingFileName.c_str(), newFileName.c_str(), dwFlags);
  POST_REALCALL

  HOOK_END

  return res;
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
    writeReroute = RerouteW::createOrNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
  POST_REALCALL

  if (res) {
    readReroute.removeMapping();

    if (writeReroute.newReroute()) {
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
  BOOL res = FALSE;

  HOOK_START_GROUP(MutExHookGroup::SHELL_FILEOP)

  if (!callContext.active()) {
    res = MoveFileWithProgressA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags);
    callContext.updateLastError();
    return res;
  }

  HOOK_END
  HOOK_START

  const auto& existingFileName = ush::string_cast<std::wstring>(lpExistingFileName);
  const auto& newFileName = ush::string_cast<std::wstring>(lpNewFileName);

  PRE_REALCALL
    res = MoveFileWithProgressW(existingFileName.c_str(), newFileName.c_str(), lpProgressRoutine, lpData, dwFlags);
  POST_REALCALL

  HOOK_END

  return res;
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
    writeReroute = RerouteW::createOrNew(context, callContext, lpNewFileName);
    updateMoveFileFlags(lpExistingFileName, lpNewFileName, readReroute, writeReroute, newFlags);
  }

  PRE_REALCALL
  res = ::MoveFileWithProgressW(readReroute.fileName(), writeReroute.fileName(), lpProgressRoutine, lpData, newFlags);
  POST_REALCALL

  if (res) {
    readReroute.removeMapping();

    if (writeReroute.newReroute()) {
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
    writeReroute = RerouteW::createOrNew(context, callContext, lpNewFileName);
  }

  PRE_REALCALL
  res = ::CopyFileExW(readReroute.fileName(), writeReroute.fileName(),
                      lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
  POST_REALCALL

  if (res && writeReroute.newReroute())
    writeReroute.insertMapping(WRITE_CONTEXT());

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

  RerouteW reroute = RerouteW::createOrNew(READ_CONTEXT(), callContext, lpPathName);

  PRE_REALCALL
  res = ::CreateDirectoryW(reroute.fileName(), lpSecurityAttributes);
  POST_REALCALL

  if (res && reroute.newReroute())
    reroute.insertMapping(WRITE_CONTEXT(), true);

  if (reroute.wasRerouted())
    LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res);

  HOOK_END

  return res;
}

DLLEXPORT BOOL WINAPI usvfs::hook_RemoveDirectoryW(
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

    reroute.removeMapping(true);
    if (reroute.wasRerouted())
      LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res);

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
    writeReroute = RerouteW::createOrNew(context, callContext, pwszNewFileName);
  }

	PRE_REALCALL
    if (!readReroute.wasRerouted() && !writeReroute.wasRerouted()) {
        res = CopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
    }
    else {
        res = CopyFile2(readReroute.fileName(), writeReroute.fileName(), pExtendedParameters);
    }
    POST_REALCALL

  if (SUCCEEDED(res) && writeReroute.newReroute())
    writeReroute.insertMapping(WRITE_CONTEXT());

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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
    res = ::WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, lpFileName);
    callContext.updateLastError();
    return res;
  }

  bool create = false;

  RerouteW reroute;
  {
    std::wstring fileName = ush::string_cast<std::wstring>(lpFileName);
    reroute = RerouteW::createOrNew(READ_CONTEXT(), callContext, fileName.c_str());
  }

  PRE_REALCALL
  res =
    ::WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, ush::string_cast<std::string>(reroute.fileName()).c_str());
  POST_REALCALL

  if (res && reroute.newReroute())
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

  if (!callContext.active() || !RerouteW::interestingPath(lpFileName)) {
    res = ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, lpFileName);
    callContext.updateLastError();
    return res;
  }

  bool create = false;

  RerouteW reroute = RerouteW::createOrNew(READ_CONTEXT(), callContext, lpFileName);

  PRE_REALCALL
  res =
    ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, reroute.fileName());
  POST_REALCALL

  if (res && reroute.newReroute())
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
