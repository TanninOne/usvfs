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
#include <boost/algorithm/string/predicate.hpp>
namespace fs = boost::filesystem;
#else
namespace fs = std::sys;
#include <filesystem>
#endif

namespace ush = usvfs::shared;
using ush::string_cast;
using ush::CodePage;

class MapTracker {
public:
  using wstring = std::wstring;

  wstring lookup(const wstring& fromPath) const {
    if (!fromPath.empty())
    {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(fromPath);
      if (find != m_map.end())
        return find->second;
    }
    return wstring();
  }

  bool contains(const wstring& fromPath) const {
    if (!fromPath.empty())
    {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(fromPath);
      if (find != m_map.end())
        return true;
    }
    return false;
  }

  void insert(const wstring& fromPath, const wstring& toPath) {
    if (fromPath.empty())
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map[fromPath] = toPath;
  }

  bool erase(const wstring& fromPath)
  {
    if (fromPath.empty())
      return false;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    return m_map.erase(fromPath);
  }

private:
  mutable std::shared_mutex m_mutex;
  std::unordered_map<wstring, wstring> m_map;
};

MapTracker k32DeleteTracker;
MapTracker k32FakeDirTracker;

class CurrentDirectoryTracker {
public:
  using wstring = std::wstring;

  bool get(wstring& currentDir, const wchar_t* forRelativePath = nullptr)
  {
    int index = m_currentDrive;
    if (forRelativePath && *forRelativePath && forRelativePath[1] == ':')
      if (!getDriveIndex(forRelativePath, index))
        spdlog::get("usvfs")->warn("CurrentDirectoryTracker::get() invalid drive letter: {}, will use current drive {}",
          string_cast<std::string>(forRelativePath), static_cast<char>('A'+ index)); // prints '@' for m_currentDrive == -1
    if (index < 0)
      return false;

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    if (m_perDrive[index].empty())
      return false;
    else {
      currentDir = m_perDrive[index];
      return true;
    }
  }

  bool set(const wstring& currentDir)
  {
    int index = -1;
    bool good = !currentDir.empty() && getDriveIndex(currentDir.c_str(), index) && currentDir[1] == ':';
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_currentDrive = good ? index : -1;
    if (good)
      m_perDrive[index] = currentDir;
    return good;
  }

private:
  static bool getDriveIndex(const wchar_t* path, int& index) {
    if (*path >= 'a' && *path <= 'z')
      index = *path - 'a';
    else if (*path >= 'A' && *path <= 'Z')
      index = *path - 'A';
    else
      return false;
    return true;
  }

  mutable std::shared_mutex m_mutex;
  wstring m_perDrive['z' - 'a' + 1];
  int m_currentDrive{ -1 };
};

CurrentDirectoryTracker k32CurrentDirectoryTracker;

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
static inline bool pathsOnDifferentDrives(LPCWSTR path1, LPCWSTR path2)
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
    {
      addDirectoryMapping(context, m_RealPath, m_FileName);

      // In case we have just created a "fake" directory, it is no longer fake and need to remove it and all its
      // parent folders from the fake map:
      std::wstring dir = m_FileName;
      while (k32FakeDirTracker.erase(dir))
        dir = fs::path(dir).parent_path().wstring();
    }
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

  void removeMapping(const usvfs::HookContext::ConstPtr &readContext, bool directory = false)
  {
    // We need to track deleted files even if they were not rerouted (i.e. files deleted from the real folder which there is
    // a virtualized mapped folder on top of it). Since we don't want to add, *every* file which is deleted we check this:
    if (!directory) {
      bool found = wasRerouted();
      if (!found)
      {
        FindCreateTarget visitor;
        usvfs::RedirectionTree::VisitorFunction visitorWrapper =
          [&](const usvfs::RedirectionTree::NodePtrT &node) { visitor(node); };
        readContext->redirectionTable()->visitPath(m_RealPath, visitorWrapper);
        if (visitor.target.get())
          found = true;
      }
      if (found)
        k32DeleteTracker.insert(m_RealPath, m_FileName);
    }

    if (wasRerouted()) {
      if (m_FileNode.get())
        m_FileNode->removeFromTree();
      else
        spdlog::get("usvfs")->warn("Node not removed: {}", string_cast<std::string>(m_FileName));

      if (!directory)
      {
        // check if this file was the last file inside a "fake" directory then remove it
        // and possibly also its fake empty parent folders:
        std::wstring parent = m_FileName;
        while (true)
        {
          parent = fs::path(parent).parent_path().wstring();
          if (k32FakeDirTracker.contains(parent))
          {
            if (RemoveDirectoryW(parent.c_str())) {
              k32FakeDirTracker.erase(parent);
              spdlog::get("usvfs")->info("removed empty fake directory: {}", string_cast<std::string>(parent));
            }
            else if (GetLastError() != ERROR_DIR_NOT_EMPTY) {
              auto error = GetLastError();
              spdlog::get("usvfs")->warn("removing fake directory failed: {}, error={}", string_cast<std::string>(parent), error);
              break;
            }
          }
          else
            break;
        }
      }
    }
  }

  static bool createFakePath(fs::path path, LPSECURITY_ATTRIBUTES securityAttributes)
  {
    // sanity and guaranteed recursion end:
    if (!path.has_relative_path())
      throw usvfs::shared::windows_error("createFakePath() refusing to create non-existing top level path: " + path.string());

    DWORD attr = GetFileAttributesW(path.c_str());
    DWORD err = GetLastError();
    if (attr != INVALID_FILE_ATTRIBUTES) {
      if (attr & FILE_ATTRIBUTE_DIRECTORY)
        return false; // if directory already exists all is good
      else
        throw usvfs::shared::windows_error("createFakePath() called on a file: " + path.string());
    }
    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
      throw usvfs::shared::windows_error("createFakePath() GetFileAttributesW failed on: " + path.string(), err);

    if (err != ERROR_FILE_NOT_FOUND) // ERROR_FILE_NOT_FOUND means parent directory already exists
      createFakePath(path.parent_path(), securityAttributes); // otherwise create parent directory (recursively)

    BOOL res = CreateDirectoryW(path.c_str(), securityAttributes);
    if (res)
      k32FakeDirTracker.insert(path.wstring(), std::wstring());
    else {
      err = GetLastError();
      throw usvfs::shared::windows_error("createFakePath() CreateDirectoryW failed on: " + path.string(), err);
    }
    return true;
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

    fs::directory_iterator end_itr;

    // cycle through the directory
    for (fs::directory_iterator itr(reroutedPath); itr != end_itr; ++itr)
    {
      // If it's not a directory, add it to the VFS, if it is recurse into it
      if (is_regular_file(itr->path())) {
        std::string fileReroutedU8 = ush::string_cast<std::string>(itr->path().wstring(), ush::CodePage::UTF8);
        spdlog::get("hooks")->info("mapping file in vfs: {}, {}",
          ush::string_cast<std::string>((originalPath / itr->path().filename()).wstring(), ush::CodePage::UTF8),
          fileReroutedU8.c_str());
        context->redirectionTable().addFile(fs::path(originalPath / itr->path().filename()), usvfs::RedirectionDataLocal(fileReroutedU8));
      } else {
        addDirectoryMapping(context, originalPath / itr->path().filename(), reroutedPath / itr->path().filename());
      }
    }

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
    WCHAR currentDirectory[MAX_PATH];
    ::GetCurrentDirectoryW(MAX_PATH, currentDirectory);
    fs::path finalPath = fs::path(currentDirectory) / inPath;
    return finalPath;
    //return winapi::wide::getFullPathName(inPath).first;
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

      result.m_Buffer = k32DeleteTracker.lookup(result.m_RealPath);
      bool found = !result.m_Buffer.empty();
      if (found)
        spdlog::get("hooks")->info("Rerouting file open to location of deleted file: {}",
          ush::string_cast<std::string>(result.m_Buffer));
      else {
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
          found = true;
        }
      }
      if (found) {
        result.m_Rerouted = true;
      }
      else
        result.m_Buffer = inPath;
    }
    else if (inPath)
      result.m_Buffer = inPath;

    wchar_t inIt = inPath[wcslen(inPath) - 1];
    std::wstring::iterator outIt = result.m_Buffer.end() - 1;
    if ((*outIt == L'\\' || *outIt == L'/') && !(inIt == L'\\' || inIt == L'/'))
      result.m_Buffer.erase(outIt);
    if (result.m_Buffer.length() >= MAX_PATH && !ush::startswith(result.m_Buffer.c_str(), LR"(\\?\)"))
      result.m_Buffer = LR"(\\?\)" + result.m_Buffer;
    std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');

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
              createFakePath(fs::path(result.m_Buffer).parent_path(), securityAttributes);
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
    std::wstring::iterator it = result.m_Buffer.end() - 1;
    wchar_t inIt = inPath[wcslen(inPath) - 1];
    std::wstring::iterator outIt = result.m_Buffer.end() - 1;
    if ((*outIt == L'\\' || *outIt == L'/') && !(inIt == L'\\' || inIt == L'/'))
      result.m_Buffer.erase(outIt);

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
    LOG_CALL().PARAM(lpFileName).PARAM(reroute.fileName()).PARAM(res).PARAM(callContext.lastError());
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

  RerouteW applicationReroute;
  RerouteW cmdReroute;
  LPWSTR cend = nullptr;

  std::wstring dllPath;
  USVFSParameters callParameters;

  { // scope for context lock
    auto context = READ_CONTEXT();

    if (RerouteW::interestingPath(lpCommandLine)) {
      // First "argument" in the commandline is the command, we need to identify it and reroute it:
      if (*lpCommandLine == '"') {
        // If the first argument is quoted we trust its is quoted correctly
        for (cend = lpCommandLine; *cend && *cend != ' '; ++cend)
          if (*cend == '"') {
            int escaped = 0;
            for (++cend; *cend && (*cend != '"' || escaped % 2 != 0); ++cend)
              escaped = *cend == '\\' ? escaped + 1 : 0;
          }

        if (*(cend - 1) == '"')
          --cend;
        auto old_cend = *cend;
        *cend = 0;
        cmdReroute = RerouteW::create(context, callContext, lpCommandLine + 1);
        *cend = old_cend;
        if (old_cend == '"')
          ++cend;
      }
      else {
        // If the first argument we have no choice but to test all the options to quote the command as the
        // real CreateProcess will do this:
        cend = lpCommandLine;
        while (true) {
          while (*cend && *cend != ' ')
            ++cend;

          auto old_cend = *cend;
          *cend = 0;
          cmdReroute = RerouteW::create(context, callContext, lpCommandLine);
          *cend = old_cend;
          if (cmdReroute.wasRerouted() || pathIsFile(cmdReroute.fileName()))
            break;

          while (*cend == ' ')
            ++cend;

          if (!*cend) {
            // if we reached the end of the string we'll just use the whole commandline as is:
            cend = nullptr;
            break;
          }
        }
      }
    }

    applicationReroute
        = RerouteW::create(context, callContext, lpApplicationName);

    dllPath        = context->dllPath();
    callParameters = context->callParameters();
  }

  std::wstring cmdline;
  if (cend && cmdReroute.fileName()) {
    auto fileName = cmdReroute.fileName();
    cmdline.reserve(wcslen(fileName) + wcslen(cend) + 2);
    if (*fileName != '"')
      cmdline += L"\"";
    cmdline += fileName;
    if (*fileName != '"')
      cmdline += L"\"";
    cmdline += cend;
  }

  PRE_REALCALL
  res = CreateProcessInternalW(
      token,
      applicationReroute.fileName(),
      cmdline.empty() ? lpCommandLine : &cmdline[0], lpProcessAttributes,
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
      .PARAM(res)
      .PARAM(callContext.lastError());
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
    bool rerouteCreate(const usvfs::HookContext::ConstPtr &context, const usvfs::HookCallContext &callContext,
      LPCWSTR lpFileName, DWORD& dwCreationDisposition, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
      enum class Open { existing, create, empty };
      Open open = Open::existing;

      std::wstring finalName = k32DeleteTracker.lookup(lpFileName);
      LPCWSTR finalNameCStr = finalName.size() != 0 ? finalName.c_str() : lpFileName;

      // Notice since we are calling our patched GetFileAttributesW here this will also check virtualized paths
      DWORD virtAttr = GetFileAttributesW(finalNameCStr);
      m_directlyAvailable = virtAttr == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
      bool isFile = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
      m_isDir = virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY);

      switch (dwCreationDisposition) {
      case CREATE_ALWAYS:
        open = Open::create;
        if (isFile || m_isDir)
          m_error = ERROR_ALREADY_EXISTS;
        break;

      case CREATE_NEW:
        if (isFile || m_isDir) {
          m_error = ERROR_FILE_EXISTS;
          return false;
        }
        else
          open = Open::create;
        break;

      case OPEN_ALWAYS:
        if (isFile || m_isDir)
          m_error = ERROR_ALREADY_EXISTS;
        else
          open = Open::create;
        break;

      case TRUNCATE_EXISTING:
        if ((dwDesiredAccess & GENERIC_WRITE) == 0) {
          m_error = ERROR_INVALID_PARAMETER;
          return false;
        }
        if (isFile || m_isDir)
          open = Open::empty;
        // if !isFile we let the OS create function set the error value
        break;
      }

      if (m_isDir && pathIsDirectory(finalNameCStr))
        m_reroute = RerouteW::noReroute(finalNameCStr);
      else
        m_reroute = RerouteW::create(context, callContext, lpFileName);

      if (m_reroute.wasRerouted() && open == Open::create && pathIsDirectory(m_reroute.fileName()))
          m_reroute = RerouteW::createNew(context, callContext, lpFileName, m_directlyAvailable, lpSecurityAttributes);

      if (!m_isDir && !isFile && !m_reroute.wasRerouted() && (open == Open::create || open == Open::empty))
      {
        m_reroute = RerouteW::createNew(context, callContext, lpFileName, m_directlyAvailable, lpSecurityAttributes);

        bool newFile = !m_reroute.wasRerouted() && pathDirectlyAvailable(m_reroute.fileName());
        if (newFile && open == Open::empty)
          // TRUNCATE_EXISTING will fail since the new file doesn't exist, so change disposition:
          dwCreationDisposition = CREATE_ALWAYS;
      }

      return true;
    }

    // rerouteNew is used for rerouting the destination of copy/move operations. Assumes that the call will be skipped if false is returned.
    bool rerouteNew(const usvfs::HookContext::ConstPtr &context, usvfs::HookCallContext &callContext, LPCWSTR lpFileName, bool replaceExisting, const char* hookName)
    {
      DWORD disposition = replaceExisting ? CREATE_ALWAYS : CREATE_NEW;
      if (!rerouteCreate(context, callContext, lpFileName, disposition, GENERIC_WRITE, nullptr)) {
        spdlog::get("hooks")->info(
          "{} guaranteed failure, skipping original call: {}, replaceExisting={}, error={}",
          hookName, ush::string_cast<std::string>(lpFileName, ush::CodePage::UTF8), replaceExisting ? "true" : "false", error());

        callContext.updateLastError(error());
        return false;
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
    bool newReroute() const { return m_reroute.newReroute(); }
    bool wasRerouted() const { return m_reroute.wasRerouted(); }
    LPCWSTR fileName() const { return m_reroute.fileName(); }

    void insertMapping(const usvfs::HookContext::Ptr &context, bool directory = false) { m_reroute.insertMapping(context, directory); }

  private:
    DWORD m_error = ERROR_SUCCESS;
    DWORD m_originalError = ERROR_SUCCESS;
    bool m_directlyAvailable = false;
    bool m_isDir = false;
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
  if (rerouter.rerouteCreate(READ_CONTEXT(), callContext, lpFileName, dwCreationDisposition, dwDesiredAccess, lpSecurityAttributes))
  {
    PRE_REALCALL
      res = ::CreateFileW(rerouter.fileName(), dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
    POST_REALCALL
    rerouter.updateResult(callContext, res != INVALID_HANDLE_VALUE);

    if (res != INVALID_HANDLE_VALUE) {
      if (rerouter.newReroute())
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
        .PARAM(rerouter.originalError())
        .PARAM(rerouter.error());
    }
  } else {
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
  if (rerouter.rerouteCreate(READ_CONTEXT(), callContext, lpFileName, dwCreationDisposition, dwDesiredAccess,
                        pCreateExParams ? pCreateExParams->lpSecurityAttributes : nullptr))
  {
    PRE_REALCALL
      res = CreateFile2(rerouter.fileName(), dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
    POST_REALCALL
    rerouter.updateResult(callContext, res != INVALID_HANDLE_VALUE);

    if (res != INVALID_HANDLE_VALUE) {
      if (rerouter.newReroute())
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
        .PARAM(rerouter.originalError())
        .PARAM(rerouter.error());
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

  fs::path canonicalFile = RerouteW::canonizePath(RerouteW::absolutePath(lpFileName));

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, canonicalFile.c_str());

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
    fs::path originalParent = canonicalFile.parent_path();
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
        .PARAM(originalError)
        .PARAM(fixedError);
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

  fs::path canonicalFile = RerouteW::canonizePath(RerouteW::absolutePath(lpFileName));

  RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, canonicalFile.c_str());

  if (reroute.wasRerouted())
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
    fs::path originalParent = canonicalFile.parent_path();
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
        .PARAM(originalError)
        .PARAM(fixedError);
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
    LOG_CALL().PARAMWRAP(reroute.fileName()).PARAM(res).PARAM(callContext.lastError());
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

  reroute.removeMapping(READ_CONTEXT());
  if (reroute.wasRerouted())
    LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(reroute.fileName()).PARAM(res).PARAM(callContext.lastError());

  HOOK_END

  return res;
}

BOOL rewriteChangedDrives(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
  const RerouteW& readReroute, const usvfs::CreateRerouter& writeReroute)
{
  return ((readReroute.wasRerouted() || writeReroute.wasRerouted())
    && pathsOnDifferentDrives(readReroute.fileName(), writeReroute.fileName())
    && !pathsOnDifferentDrives(lpExistingFileName, lpNewFileName));
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
  CreateRerouter writeReroute;
  bool callOriginal = true;
  DWORD newFlags = 0;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, lpExistingFileName);
    callOriginal = writeReroute.rerouteNew(context, callContext, lpNewFileName, false, "hook_MoveFileW");
  }

  if (callOriginal)
  {
    bool movedDrives = rewriteChangedDrives(lpExistingFileName, lpNewFileName, readReroute, writeReroute);
    if (movedDrives) newFlags |= MOVEFILE_COPY_ALLOWED;

    bool isDirectory = pathIsDirectory(readReroute.fileName());

    PRE_REALCALL
    if (isDirectory && movedDrives) {
      SHFILEOPSTRUCTW sf = { 0 };
      sf.wFunc = FO_MOVE;
      sf.hwnd = 0;
      sf.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI;
      sf.pFrom = readReroute.fileName();
      sf.pTo = writeReroute.fileName();
      int shRes = ::SHFileOperationW(&sf);
      switch (shRes) {
      case 0x78:
        callContext.updateLastError(ERROR_ACCESS_DENIED);
        break;
      case 0x7C:
        callContext.updateLastError(ERROR_FILE_NOT_FOUND);
        break;
      case 0x7E:
      case 0x80:
        callContext.updateLastError(ERROR_FILE_EXISTS);
        break;
      default:
        callContext.updateLastError(shRes);
      }
      res = shRes == 0;
    } else if (newFlags)
      res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
    else
      res = ::MoveFileW(readReroute.fileName(), writeReroute.fileName());
    POST_REALCALL

    if (res) SetLastError(ERROR_SUCCESS);

    writeReroute.updateResult(callContext, res);

    if (res) {
      readReroute.removeMapping(READ_CONTEXT(), isDirectory); // Updating the rerouteCreate to check deleted file entries should make this okay

      if (writeReroute.newReroute()) {
        if (isDirectory)
          RerouteW::addDirectoryMapping(WRITE_CONTEXT(), fs::path(lpNewFileName), fs::path(writeReroute.fileName()));
        else
          writeReroute.insertMapping(WRITE_CONTEXT());
      }
    }

    if (readReroute.wasRerouted() || writeReroute.wasRerouted() || writeReroute.changedError())
      LOG_CALL()
      .PARAMWRAP(readReroute.fileName())
      .PARAMWRAP(writeReroute.fileName())
      .PARAMWRAP(newFlags)
      .PARAM(res)
      .PARAM(writeReroute.originalError())
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
  CreateRerouter writeReroute;
  bool callOriginal = true;
  DWORD newFlags = dwFlags;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, lpExistingFileName);
    callOriginal = writeReroute.rerouteNew(context, callContext, lpNewFileName,
        newFlags & MOVEFILE_REPLACE_EXISTING, "hook_MoveFileExW");
  }

  if (callOriginal)
  {
    bool movedDrives = rewriteChangedDrives(lpExistingFileName, lpNewFileName, readReroute, writeReroute);

    bool isDirectory = pathIsDirectory(readReroute.fileName());

    PRE_REALCALL
    if (isDirectory && movedDrives) {
      SHFILEOPSTRUCTW sf = { 0 };
      sf.wFunc = FO_MOVE;
      sf.hwnd = 0;
      sf.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI;
      sf.pFrom = readReroute.fileName();
      sf.pTo = writeReroute.fileName();
      int shRes = ::SHFileOperationW(&sf);
      switch (shRes) {
      case 0x78:
        callContext.updateLastError(ERROR_ACCESS_DENIED);
        break;
      case 0x7C:
        callContext.updateLastError(ERROR_FILE_NOT_FOUND);
        break;
      case 0x7E:
      case 0x80:
        callContext.updateLastError(ERROR_FILE_EXISTS);
        break;
      default:
        callContext.updateLastError(shRes);
      }
      res = shRes == 0;
    } else
      res = ::MoveFileExW(readReroute.fileName(), writeReroute.fileName(), newFlags);
    POST_REALCALL

    if (res) SetLastError(ERROR_SUCCESS);

    writeReroute.updateResult(callContext, res);

    if (res) {
      readReroute.removeMapping(READ_CONTEXT(), isDirectory); // Updating the rerouteCreate to check deleted file entries should make this okay

      if (writeReroute.newReroute()) {
        if (isDirectory)
          RerouteW::addDirectoryMapping(WRITE_CONTEXT(), fs::path(lpNewFileName), fs::path(writeReroute.fileName()));
        else
          writeReroute.insertMapping(WRITE_CONTEXT());
      }
    }

    if (readReroute.wasRerouted() || writeReroute.wasRerouted() || writeReroute.changedError())
      LOG_CALL()
      .PARAMWRAP(readReroute.fileName())
      .PARAMWRAP(writeReroute.fileName())
      .PARAMWRAP(dwFlags)
      .PARAMWRAP(newFlags)
      .PARAM(res)
      .PARAM(writeReroute.originalError())
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
  CreateRerouter writeReroute;
  bool callOriginal = true;
  DWORD newFlags = dwFlags;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, lpExistingFileName);
    callOriginal = writeReroute.rerouteNew(context, callContext, lpNewFileName,
        newFlags & MOVEFILE_REPLACE_EXISTING, "hook_MoveFileWithProgressW");
  }

  if (callOriginal)
  {
    bool movedDrives = rewriteChangedDrives(lpExistingFileName, lpNewFileName, readReroute, writeReroute);
    if (movedDrives) newFlags |= MOVEFILE_COPY_ALLOWED;

	bool isDirectory = pathIsDirectory(readReroute.fileName());

  PRE_REALCALL
	if (isDirectory && movedDrives) {
		SHFILEOPSTRUCTW sf = { 0 };
		sf.wFunc = FO_MOVE;
		sf.hwnd = 0;
		sf.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI;
		sf.pFrom = readReroute.fileName();
		sf.pTo = writeReroute.fileName();
		int shRes = ::SHFileOperationW(&sf);
		switch (shRes) {
		case 0x78:
			callContext.updateLastError(ERROR_ACCESS_DENIED);
			break;
		case 0x7C:
			callContext.updateLastError(ERROR_FILE_NOT_FOUND);
			break;
		case 0x7E:
		case 0x80:
			callContext.updateLastError(ERROR_FILE_EXISTS);
			break;
		default:
			callContext.updateLastError(shRes);
		}
		res = shRes == 0;
	} else
		res = ::MoveFileWithProgressW(readReroute.fileName(), writeReroute.fileName(), lpProgressRoutine, lpData, newFlags);
  POST_REALCALL

  if (res) SetLastError(ERROR_SUCCESS);

  writeReroute.updateResult(callContext, res);

  if (res) {
    readReroute.removeMapping(READ_CONTEXT(), isDirectory); // Updating the rerouteCreate to check deleted file entries should make this okay

    if (writeReroute.newReroute()) {
      if (isDirectory)
        RerouteW::addDirectoryMapping(WRITE_CONTEXT(), fs::path(lpNewFileName), fs::path(writeReroute.fileName()));
      else
        writeReroute.insertMapping(WRITE_CONTEXT());
    }
  }

  if (readReroute.wasRerouted() || writeReroute.wasRerouted() || writeReroute.changedError())
    LOG_CALL()
    .PARAMWRAP(readReroute.fileName())
    .PARAMWRAP(writeReroute.fileName())
    .PARAMWRAP(dwFlags)
    .PARAMWRAP(newFlags)
    .PARAM(res)
    .PARAM(writeReroute.originalError())
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
  CreateRerouter writeReroute;
  bool callOriginal = true;

  {
    auto context = READ_CONTEXT();
    readReroute  = RerouteW::create(context, callContext, lpExistingFileName);
    callOriginal = writeReroute.rerouteNew(context, callContext, lpNewFileName,
      (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) == 0, "hook_CopyFileExW");
  }

  if (callOriginal)
  {
    PRE_REALCALL
    res = ::CopyFileExW(readReroute.fileName(), writeReroute.fileName(),
                        lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    POST_REALCALL
    writeReroute.updateResult(callContext, res);

    if (res && writeReroute.newReroute())
      writeReroute.insertMapping(WRITE_CONTEXT());

    if (readReroute.wasRerouted() || writeReroute.wasRerouted() || writeReroute.changedError())
      LOG_CALL()
        .PARAMWRAP(readReroute.fileName())
        .PARAMWRAP(writeReroute.fileName())
        .PARAM(res)
        .PARAM(writeReroute.originalError())
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

  std::wstring actualCWD;

  if (!k32CurrentDirectoryTracker.get(actualCWD)) {
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

  if (nBufferLength)
    LOG_CALL()
      .PARAMWRAP(std::wstring(lpBuffer, res))
      .PARAM(nBufferLength)
      .PARAM(actualCWD.size())
      .PARAM(res)
      .PARAM(callContext.lastError());

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

  const fs::path& realPath = RerouteW::canonizePath(RerouteW::absolutePath(lpPathName));
  const std::wstring& realPathStr = realPath.wstring();
  std::wstring finalRoute;
  BOOL found = FALSE;

  if (fs::exists(realPath))
    finalRoute = realPathStr;
  else {
    WCHAR processDir[MAX_PATH];
    if (::GetModuleFileNameW(NULL, processDir, MAX_PATH) != 0 && ::PathRemoveFileSpecW(processDir)) {
      WCHAR processName[MAX_PATH];
      ::GetModuleFileNameW(NULL, processName, MAX_PATH);
      fs::path routedName = realPath / processName;
      RerouteW rerouteTest = RerouteW::create(READ_CONTEXT(), callContext, routedName.wstring().c_str());
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
      RerouteW reroute = RerouteW::create(READ_CONTEXT(), callContext, realPathStr.c_str());
      finalRoute = reroute.fileName();
    }
  }

  PRE_REALCALL
  res = ::SetCurrentDirectoryW(finalRoute.c_str());
  POST_REALCALL

  if (res)
    if (!k32CurrentDirectoryTracker.set(realPathStr))
      spdlog::get("usvfs")->warn("Updating actual current directory failed: {} ?!", string_cast<std::string>(realPathStr));


  LOG_CALL()
    .PARAMWRAP(lpPathName)
    .PARAMWRAP(realPathStr.c_str())
    .PARAMWRAP(finalRoute.c_str())
    .PARAM(res)
    .PARAM(callContext.lastError());

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
    LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res).PARAM(callContext.lastError());

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

    reroute.removeMapping(READ_CONTEXT(), true);
    if (reroute.wasRerouted())
      LOG_CALL().PARAMWRAP(lpPathName).PARAMWRAP(reroute.fileName()).PARAM(res).PARAM(callContext.lastError());

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

  std::string resolvedWithCMD;

  std::wstring actualCWD;
  fs::path filePath = lpFileName;
  if (k32CurrentDirectoryTracker.get(actualCWD, filePath.wstring().c_str())) {
    if (!filePath.is_absolute())
      resolvedWithCMD =
        ush::string_cast<std::string>((actualCWD / filePath.relative_path()).wstring());
  }

  PRE_REALCALL
  res = ::GetFullPathNameA(
    resolvedWithCMD.empty() ? lpFileName : resolvedWithCMD.c_str(), nBufferLength, lpBuffer, lpFilePart);
  POST_REALCALL

  if (false && nBufferLength)
    LOG_CALL()
      .PARAMWRAP(lpFileName)
      .PARAMWRAP(resolvedWithCMD.c_str())
      .PARAMWRAP(std::string(lpBuffer, res).c_str())
      .PARAM(nBufferLength)
      .PARAM(res)
      .PARAM(callContext.lastError());

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

  std::wstring resolvedWithCMD;

  std::wstring actualCWD;
  if (k32CurrentDirectoryTracker.get(actualCWD, lpFileName)) {
    fs::path filePath = lpFileName;
    if (!filePath.is_absolute())
      resolvedWithCMD = (actualCWD / filePath.relative_path()).wstring();
  }

  PRE_REALCALL
  res = ::GetFullPathNameW(
    resolvedWithCMD.empty() ? lpFileName : resolvedWithCMD.c_str(), nBufferLength, lpBuffer, lpFilePart);
  POST_REALCALL

  if (false && nBufferLength)
   LOG_CALL()
    .PARAMWRAP(lpFileName)
    .PARAMWRAP(resolvedWithCMD)
    .PARAMWRAP(std::wstring(lpBuffer, res))
    .PARAM(nBufferLength)
    .PARAM(res)
    .PARAM(callContext.lastError());

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
          .PARAM(res)
          .PARAM(callContext.lastError());
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

  WCHAR *tempPath = new WCHAR[MAX_PATH];
  ::GetTempPathW(MAX_PATH, tempPath);
  ::GetLongPathNameW(tempPath, tempPath, MAX_PATH);
  std::wstring tempPathStr(tempPath);
  tempPathStr.pop_back(); // Remove trailing slash
  delete[] tempPath;

  fs::path finalPath;
  RerouteW reroute;
  fs::path originalPath;

  bool usedRewrite = false;

  
  if (boost::algorithm::icontains(lpFileName, tempPathStr)) {
    PRE_REALCALL
    //Force the mutEXHook to match NtQueryDirectoryFile so it calls the non hooked NtQueryDirectoryFile.
    FunctionGroupLock lock(MutExHookGroup::FIND_FILES);
    res = ::FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    POST_REALCALL
  } else {
    // We need to do some trickery here, since we only want to use the hooked NtQueryDirectoryFile for rerouted locations we need to check if the Directory path has been routed instead of the full path.
    originalPath = RerouteW::canonizePath(RerouteW::absolutePath(lpFileName));
    PRE_REALCALL
    res = ::FindFirstFileExW(originalPath.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    POST_REALCALL

    if (res == INVALID_HANDLE_VALUE) {
      fs::path searchPath = originalPath.filename();
      fs::path parentPath = originalPath.parent_path();
      std::wstring findPath = parentPath.wstring();
      while (findPath.find(L"*?<>\"", 0, 1) != std::wstring::npos) {
        searchPath = parentPath.filename() / searchPath;
        parentPath = parentPath.parent_path();
        findPath = parentPath.wstring();
      }
      reroute = RerouteW::create(READ_CONTEXT(), callContext, parentPath.c_str());
      if (reroute.wasRerouted()) {
        finalPath = reroute.fileName();
        finalPath /= searchPath.wstring();
      }
      if (!finalPath.empty()) {
        PRE_REALCALL
        usedRewrite = true;
        res = ::FindFirstFileExW(finalPath.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
        POST_REALCALL
      }
    }
  }

  if (res != INVALID_HANDLE_VALUE) {
  // store the original search path for use during iteration
  WRITE_CONTEXT()
      ->customData<SearchHandleMap>(SearchHandles)[res]
      = lpFileName;
  }

  LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(tempPathStr.c_str());
  LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(originalPath.c_str()).PARAM(res).PARAM(callContext.lastError());
  if (usedRewrite)
    LOG_CALL().PARAMWRAP(lpFileName).PARAMWRAP(finalPath.c_str()).PARAM(res).PARAM(callContext.lastError());

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
  CreateRerouter writeReroute;
  bool callOriginal = true;

  {
    auto context = READ_CONTEXT();
    readReroute = RerouteW::create(context, callContext, pwszExistingFileName);
    callOriginal = writeReroute.rerouteNew(context, callContext, pwszNewFileName,
      pExtendedParameters && (pExtendedParameters->dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) == 0, "hook_CopyFile2");
  }

  if (callOriginal)
  {
    PRE_REALCALL
    res = CopyFile2(readReroute.fileName(), writeReroute.fileName(), pExtendedParameters);
    POST_REALCALL
    writeReroute.updateResult(callContext, SUCCEEDED(res));

    if (SUCCEEDED(res) && writeReroute.newReroute())
      writeReroute.insertMapping(WRITE_CONTEXT());

    if (readReroute.wasRerouted() || writeReroute.wasRerouted() || writeReroute.changedError())
      LOG_CALL()
      .PARAMWRAP(readReroute.fileName())
      .PARAMWRAP(writeReroute.fileName())
      .PARAM(res)
      .PARAM(writeReroute.originalError())
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
      .PARAM(callContext.lastError());
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
      .PARAM(callContext.lastError());
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
      .PARAM(callContext.lastError());
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
      .PARAM(callContext.lastError());
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

  CreateRerouter reroute;
  bool callOriginal = reroute.rerouteNew(READ_CONTEXT(), callContext,
      ush::string_cast<std::wstring>(lpFileName).c_str(), true, "hook_WritePrivateProfileStringA");

  if (callOriginal)
  {
    PRE_REALCALL
    res = ::WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, ush::string_cast<std::string>(reroute.fileName()).c_str());
    POST_REALCALL
    reroute.updateResult(callContext, res);

    if (res && reroute.newReroute())
      reroute.insertMapping(WRITE_CONTEXT());

    if (reroute.wasRerouted() || reroute.changedError())
      LOG_CALL()
        .PARAM(lpAppName)
        .PARAM(lpKeyName)
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAM(reroute.originalError())
        .PARAM(callContext.lastError());
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

  CreateRerouter reroute;
  bool callOriginal = reroute.rerouteNew(READ_CONTEXT(), callContext,
    lpFileName, true, "hook_WritePrivateProfileStringW");

  if (callOriginal)
  {
    PRE_REALCALL
    res = ::WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, reroute.fileName());
    POST_REALCALL
    reroute.updateResult(callContext, res);

    if (res && reroute.newReroute())
      reroute.insertMapping(WRITE_CONTEXT());

    if (reroute.wasRerouted() || reroute.changedError())
      LOG_CALL()
        .PARAM(lpAppName)
        .PARAM(lpKeyName)
        .PARAMWRAP(lpFileName)
        .PARAMWRAP(reroute.fileName())
        .PARAMHEX(res)
        .PARAM(reroute.originalError())
        .PARAM(callContext.lastError());
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
