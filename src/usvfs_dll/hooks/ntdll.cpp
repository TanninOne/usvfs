#include "ntdll.h"
#include "sharedids.h"
#include <loghelpers.h>
#include "../hookcontext.h"
#include "../hookcallcontext.h"
#include "../stringcast_boost.h"
#include <usvfs.h>
#pragma warning(push, 3)
#include <boost/scoped_array.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/locale.hpp>
//#include <boost/thread/mutex.hpp>
#pragma warning(pop)
#include <string>
#include <deque>
#include <vector>
#include <set>
#include <map>
#include <cstdint>
#include <cwctype>
#include <codecvt>
#include <locale>
#include <windows_error.h>
#include <stringutils.h>
#include <stringcast.h>
#include <scopeguard.h>
#include <addrtools.h>
#include <unicodestring.h>
#include <windows.h>
#include <fileapi.h>

#pragma warning(disable : 4996)

namespace ulog = usvfs::log;
namespace ush  = usvfs::shared;
namespace bfs  = boost::filesystem;

using usvfs::UnicodeString;

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005

template <typename T>
using unique_ptr_deleter = std::unique_ptr<T, void (*)(T *)>;

UnicodeString CreateUnicodeString(const OBJECT_ATTRIBUTES *objectAttributes)
{
  UnicodeString result;
  if (objectAttributes->RootDirectory != nullptr) {
    try {
      result.setFromHandle(objectAttributes->RootDirectory);
    } catch (const std::exception &e) {
      spdlog::get("usvfs")->info("exception: {0}", e.what());
    }
  }
  if (objectAttributes->ObjectName != nullptr) {
    result.appendPath(objectAttributes->ObjectName);
  }
  return result;
}

std::ostream &operator<<(std::ostream &os, const _UNICODE_STRING &str)
{
  try {
    // TODO this does not correctly support surrogate pairs
    // since the size used here is the number of 16-bit characters in the buffer
    // whereas
    // toNarrow expects the actual number of characters.
    // It will always underestimate though, so worst case scenario we truncate
    // the string
    os << ush::string_cast<std::string>(str.Buffer, ush::CodePage::UTF8,
                                        str.Length / sizeof(WCHAR));
  } catch (const std::exception &e) {
    os << e.what();
  }

  return os;
}

std::ostream &operator<<(std::ostream &os, POBJECT_ATTRIBUTES attr)
{
  return operator<<(os, *attr->ObjectName);
}

std::pair<UnicodeString, bool>
applyReroute(const usvfs::HookContext::ConstPtr &context,
             const usvfs::HookCallContext &callContext,
             const UnicodeString &inPath)
{
  std::pair<UnicodeString, bool> result;
  result.first  = inPath;
  result.second = false;

  if (callContext.active()) {
    // see if the file exists in the redirection tree
    std::string lookupPath = ush::string_cast<std::string>(
        static_cast<LPCWSTR>(result.first) + 4, ush::CodePage::UTF8);
    auto node = context->redirectionTable()->findNode(lookupPath.c_str());
    // if so, replace the file name with the path to the mapped file
    if ((node.get() != nullptr) && (!node->data().linkTarget.empty() || node->isDirectory())) {
      std::wstring reroutePath;

      if (node->data().linkTarget.length() > 0)
      {
        reroutePath = ush::string_cast<std::wstring>(
          node->data().linkTarget.c_str(), ush::CodePage::UTF8);
      }
      else
      {
        reroutePath = ush::string_cast<std::wstring>(
          node->path().c_str(),
          ush::CodePage::UTF8);
      } 
      if ((*reroutePath.rbegin() == L'\\') && (*lookupPath.rbegin() != '\\')) {
        reroutePath.resize(reroutePath.size() - 1);
      }
      std::replace(reroutePath.begin(), reroutePath.end(), L'/', L'\\');
      if (reroutePath[1] == L'\\')
        reroutePath[1] = L'?';
      result.first.set(reroutePath.c_str());
      result.second = true;
    }
  }
  return result;
}

struct FindCreateTarget {
  usvfs::RedirectionTree::NodePtrT target;
  void operator()(usvfs::RedirectionTree::NodePtrT node)
  {
    if (node->hasFlag(usvfs::shared::FLAG_CREATETARGET)) {
      target = node;
    }
  }
};

std::pair<UnicodeString, UnicodeString>
findCreateTarget(const usvfs::HookContext::ConstPtr &context,
                 const UnicodeString &inPath)
{
  std::pair<UnicodeString, UnicodeString> result;
  result.first  = inPath;
  result.second = UnicodeString();

  std::string lookupPath = ush::string_cast<std::string>(
      static_cast<LPCWSTR>(result.first) + 4, ush::CodePage::UTF8);
  FindCreateTarget visitor;
  usvfs::RedirectionTree::VisitorFunction visitorWrapper =
      [&](const usvfs::RedirectionTree::NodePtrT &node) { visitor(node); };
  context->redirectionTable()->visitPath(lookupPath, visitorWrapper);
  if (visitor.target.get() != nullptr) {
    bfs::path relativePath
        = ush::make_relative(visitor.target->path(), bfs::path(lookupPath));

    bfs::path target(visitor.target->data().linkTarget.c_str());
    target /= relativePath;

    result.second = UnicodeString(target.wstring().c_str());
    winapi::ex::wide::createPath(target.parent_path().wstring().c_str());
  }
  return result;
}


std::pair<UnicodeString, bool>
applyReroute(const usvfs::HookContext::ConstPtr &context,
             const usvfs::HookCallContext &callContext,
             POBJECT_ATTRIBUTES inAttributes)
{
  return applyReroute(context, callContext, CreateUnicodeString(inAttributes));
}

ULONG StructMinSize(FILE_INFORMATION_CLASS infoClass)
{
  switch (infoClass) {
    case FileBothDirectoryInformation:
      return sizeof(FILE_BOTH_DIR_INFORMATION);
    case FileDirectoryInformation:
      return sizeof(FILE_DIRECTORY_INFORMATION);
    case FileFullDirectoryInformation:
      return sizeof(FILE_FULL_DIR_INFORMATION);
    case FileIdBothDirectoryInformation:
      return sizeof(FILE_ID_BOTH_DIR_INFORMATION);
    case FileIdFullDirectoryInformation:
      return sizeof(FILE_ID_FULL_DIR_INFORMATION);
    case FileNamesInformation:
      return sizeof(FILE_NAMES_INFORMATION);
    case FileObjectIdInformation:
      return sizeof(FILE_OBJECTID_INFORMATION);
    case FileReparsePointInformation:
      return sizeof(FILE_REPARSE_POINT_INFORMATION);
    default:
      return 0;
  }
}

void GetInfoData(LPCVOID address, FILE_INFORMATION_CLASS infoClass,
                 ULONG &offset, std::wstring &fileName)
{
  switch (infoClass) {
    case FileBothDirectoryInformation: {
      const FILE_BOTH_DIR_INFORMATION *info
          = reinterpret_cast<const FILE_BOTH_DIR_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileDirectoryInformation: {
      const FILE_DIRECTORY_INFORMATION *info
          = reinterpret_cast<const FILE_DIRECTORY_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileNamesInformation: {
      const FILE_NAMES_INFORMATION *info
          = reinterpret_cast<const FILE_NAMES_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileIdFullDirectoryInformation: {
      const FILE_ID_FULL_DIR_INFORMATION *info
          = reinterpret_cast<const FILE_ID_FULL_DIR_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileFullDirectoryInformation: {
      const FILE_FULL_DIR_INFORMATION *info
          = reinterpret_cast<const FILE_FULL_DIR_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileIdBothDirectoryInformation: {
      const FILE_ID_BOTH_DIR_INFORMATION *info
          = reinterpret_cast<const FILE_ID_BOTH_DIR_INFORMATION *>(address);
      offset = info->NextEntryOffset;
      fileName
          = std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileObjectIdInformation: {
      offset = sizeof(FILE_OBJECTID_INFORMATION);
    } break;
    case FileReparsePointInformation: {
      offset = sizeof(FILE_REPARSE_POINT_INFORMATION);
    } break;
    default: {
      offset = ULONG_MAX;
    } break;
  }
}

template <typename T>
void SetInfoFilenameImpl(T *info, const std::wstring &fileName)
{
  // not sure if the filename is supposed to be zero terminated but I did get
  // invalid
  // filenames when the buffer wasn't zeroed
  memset(info->FileName, L'\0', info->FileNameLength);

  info->FileNameLength = static_cast<ULONG>(fileName.length() * sizeof(WCHAR));
  memcpy(info->FileName, fileName.c_str(), info->FileNameLength + 1);
}

// like wcsrchr except that the position to start searching can be specified and
// the string doesn't
// need to be 0-terminated
const wchar_t *wcsrevsearch(const wchar_t *cur, const wchar_t *start,
                            wchar_t ch)
{
  for (; cur > start; --cur) {
    if (*cur == ch) {
      return cur;
    }
  }
  return nullptr;
}

template <typename T>
void SetInfoFilenameImplSN(T *info, const std::wstring &fileName)
{
  memset(info->FileName, L'\0', info->FileNameLength);
  info->FileNameLength = static_cast<ULONG>(fileName.length() * sizeof(WCHAR));
  memcpy(info->FileName, fileName.c_str(),
         info->FileNameLength); // doesn't need to be 0-terminated

  if (info->ShortNameLength > 0) {
    info->ShortNameLength = static_cast<CCHAR>(
        GetShortPathNameW(fileName.c_str(), info->ShortName, 8));
  }
}

void SetInfoFilename(LPVOID address, FILE_INFORMATION_CLASS infoClass,
                     const std::wstring &fileName)
{
  switch (infoClass) {
    case FileBothDirectoryInformation: {
      SetInfoFilenameImplSN(
          reinterpret_cast<FILE_BOTH_DIR_INFORMATION *>(address), fileName);
    } break;
    case FileDirectoryInformation: {
      SetInfoFilenameImpl(
          reinterpret_cast<FILE_DIRECTORY_INFORMATION *>(address), fileName);
    } break;
    case FileNamesInformation: {
      SetInfoFilenameImpl(reinterpret_cast<FILE_NAMES_INFORMATION *>(address),
                          fileName);
    } break;
    case FileIdFullDirectoryInformation: {
      SetInfoFilenameImpl(
          reinterpret_cast<FILE_ID_FULL_DIR_INFORMATION *>(address), fileName);
    } break;
    case FileFullDirectoryInformation: {
      SetInfoFilenameImpl(
          reinterpret_cast<FILE_FULL_DIR_INFORMATION *>(address), fileName);
    } break;
    case FileIdBothDirectoryInformation: {
      SetInfoFilenameImplSN(
          reinterpret_cast<FILE_ID_BOTH_DIR_INFORMATION *>(address),
          fileName);
    } break;
    default: {
      // NOP
    } break;
  }
}

void SetInfoOffset(LPVOID address, FILE_INFORMATION_CLASS infoClass,
                   ULONG offset)
{
  switch (infoClass) {
    case FileBothDirectoryInformation: {
      reinterpret_cast<FILE_BOTH_DIR_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    case FileDirectoryInformation: {
      reinterpret_cast<FILE_DIRECTORY_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    case FileNamesInformation: {
      reinterpret_cast<FILE_NAMES_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    case FileIdFullDirectoryInformation: {
      reinterpret_cast<FILE_ID_FULL_DIR_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    case FileFullDirectoryInformation: {
      reinterpret_cast<FILE_FULL_DIR_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    case FileIdBothDirectoryInformation: {
      reinterpret_cast<FILE_ID_BOTH_DIR_INFORMATION *>(address)->NextEntryOffset
          = offset;
    } break;
    default: {
      // NOP
    } break;
  }
}

int NextDividableBy(int number, int divider)
{
  return static_cast<int>(
      ceilf(static_cast<float>(number) / static_cast<float>(divider))
      * divider);
}

std::string toHex(PVOID buffer, ULONG size)
{
  fmt::MemoryWriter stream;
  unsigned char *bufferChar = reinterpret_cast<unsigned char *>(buffer);
  for (size_t i = 0; i < size; ++i) {
    stream << fmt::pad(fmt::hex(bufferChar[i]), 2, '0');
    if (i < size - 1) {
      stream << ((i % 16 == 15) ? "\n" : " ");
    }
  }

  return stream.str();
}

NTSTATUS addNtSearchData(HANDLE hdl, PUNICODE_STRING FileName,
                         const std::wstring &fakeName,
                         FILE_INFORMATION_CLASS FileInformationClass,
                         PVOID &buffer, ULONG &bufferSize,
                         std::set<std::wstring> &foundFiles, HANDLE event,
                         PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                         BOOLEAN returnSingleEntry)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;
  if (hdl != INVALID_HANDLE_VALUE) {
    PVOID lastValidRecord = nullptr;
    PVOID bufferInit = buffer;
    IO_STATUS_BLOCK status;
    res = NtQueryDirectoryFile(hdl, event, apcRoutine, apcContext, &status,
                               buffer, bufferSize, FileInformationClass,
                               returnSingleEntry, FileName, FALSE);

    if ((res != STATUS_SUCCESS) || (status.Information <= 0)) {
      bufferSize = 0UL;
    } else {
      ULONG totalOffset   = 0;
      PVOID lastSkipPos   = nullptr;

      while (totalOffset < status.Information) {
        ULONG offset;
        std::wstring fileName;
        GetInfoData(buffer, FileInformationClass, offset, fileName);
        // in case this is a single-file search result and the specified
        // filename differs from the file name found, replace it in the
        // information structure
        if ((totalOffset == 0) && (offset == 0) && (fakeName.length() > 0)) {
          // if the fake name is larger than what is in the buffer and there is
          // not enough room, that's a buffer overflow
          if ((fakeName.length() > fileName.length())
              && ((fakeName.length() - fileName.length())
                  > (bufferSize - status.Information))) {
            res = STATUS_BUFFER_OVERFLOW;
            break;
          }
          // WARNING for the case where the fake name is longer this needs to
          // move back all further results and update the offset first
          SetInfoFilename(buffer, FileInformationClass, fakeName);
          fileName = fakeName;
        }
        bool add = true;
        if (fileName.length() > 0) {
          auto insertRes = foundFiles.insert(ush::to_upper(fileName));
          add      = insertRes.second; // add only if we didn't find this file before
        }
        if (!add) {
          if (lastSkipPos == nullptr) {
            lastSkipPos = buffer;
          }
        } else {
          if (lastSkipPos != nullptr) {
            memmove(lastSkipPos, buffer, status.Information - totalOffset);
            ULONG delta = static_cast<ULONG>(ush::AddrDiff(buffer, lastSkipPos));
            totalOffset -= delta;

            buffer = lastSkipPos;
            lastSkipPos = nullptr;
          }
          lastValidRecord = buffer;
        }

        if (offset == 0) {
          offset = static_cast<ULONG>(status.Information) - totalOffset;
        }
        buffer = ush::AddrAdd(buffer, offset);
        totalOffset += offset;
      }

      if (lastSkipPos != nullptr) {
        buffer = lastSkipPos;
        bufferSize = static_cast<ULONG>(ush::AddrDiff(buffer, bufferInit));
        // null out the unused rest if there is some
        memset(lastSkipPos, 0, status.Information - bufferSize);
      } else {
        bufferSize = static_cast<ULONG>(ush::AddrDiff(buffer, bufferInit));
      }
    }
    if (lastValidRecord != nullptr) {
      SetInfoOffset(lastValidRecord, FileInformationClass, 0);
    }
  }
  return res;
}

DATA_ID(SearchInfo);

struct Searches {
  struct Info {
    struct VirtualMatch {
      // full path to where the file/directory actually is
      std::wstring realPath;
      // virtual filename (only filename since it has to be within the searched
      // directory)
      // this is left empty when a folder with all its content is mapped to the
      // search directory
      std::wstring virtualName;
    };

    Info() : currentSearchHandle(INVALID_HANDLE_VALUE)
    {
    }
    std::set<std::wstring> foundFiles;
    HANDLE currentSearchHandle;
    std::vector<VirtualMatch> virtualMatches;
    UnicodeString searchPattern;
    bool regularComplete{false};
  };

  Searches() = default;

  // must provide a special copy constructor because boost::mutex is
  // non-copyable
  Searches(const Searches &reference) : info(reference.info)
  {
  }

  Searches &operator=(const Searches &) = delete;

  std::recursive_mutex queryMutex;

  std::map<HANDLE, Info> info;
};

void gatherVirtualEntries(const UnicodeString &dirName,
                          const usvfs::RedirectionTreeContainer &redir,
                          PUNICODE_STRING FileName, Searches::Info &info)
{
  LPCWSTR dirNameW = static_cast<LPCWSTR>(dirName);
  // fix directory name. I'd love to know why microsoft sometimes uses "\??\" vs
  // "\\?\"
  if ((wcsncmp(dirNameW, LR"(\\?\)", 4) == 0)
      || (wcsncmp(dirNameW, LR"(\??\)", 4) == 0)) {
    dirNameW += 4;
  }
  auto node = redir->findNode(boost::filesystem::path(dirNameW));
  if (node.get() != nullptr) {
    std::string searchPattern = FileName != nullptr
                                    ? ush::string_cast<std::string>(
                                          FileName->Buffer, ush::CodePage::UTF8)
                                    : "*.*";

    for (const auto &subNode : node->find(searchPattern)) {
      if (((subNode->data().linkTarget.length() > 0) || subNode->isDirectory())
          && !subNode->hasFlag(usvfs::shared::FLAG_DUMMY)) {
        std::wstring vName = ush::string_cast<std::wstring>(
            subNode->name(), ush::CodePage::UTF8);

        Searches::Info::VirtualMatch m;
        if (subNode->data().linkTarget.length() > 0)
        {
          m = { ush::string_cast<std::wstring>(subNode->data().linkTarget.c_str(),
                                         ush::CodePage::UTF8), vName };
        }
        else
        {
          m = { ush::string_cast<std::wstring>(subNode->path().c_str(),
            ush::CodePage::UTF8), vName };
        }
              
        info.virtualMatches.push_back(m);
        info.foundFiles.insert(ush::to_upper(vName));
      }
    }
  }
}

/**
 * @brief insert a virtual entry into the search result
 * @param FileInformation
 * @param FileInformationClass
 * @param info
 * @param realPath path were the actual file resides
 * @param virtualName virtual file name (without path). will often be the same
 *        as the name component of realpath
 * @param ReturnSingleEntry
 * @param dataRead
 * @return true if a virtual result was added, false if the search handle in the
 *         info object yields no more results
 */
bool addVirtualSearchResult(PVOID &FileInformation,
                            FILE_INFORMATION_CLASS FileInformationClass,
                            Searches::Info &info, const std::wstring &realPath,
                            const std::wstring &virtualName,
                            BOOLEAN ReturnSingleEntry, ULONG &dataRead)
{
  // this opens a search in the real location, then copies the information about
  // files we care about (the ones being mapped) to the result we intend to
  // return
  bfs::path fullPath(realPath);
  if (fullPath.filename().wstring() == L".") {
    fullPath = fullPath.parent_path();
  }
  if (info.currentSearchHandle == INVALID_HANDLE_VALUE) {
    std::wstring dirName     = fullPath.parent_path().wstring();
    if (dirName.length() >= MAX_PATH && !ush::startswith(dirName.c_str(), LR"(\\?\)"))
      dirName = LR"(\\?\)" + dirName;
    info.currentSearchHandle = CreateFileW(
        dirName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  }
  std::wstring fileName = ush::string_cast<std::wstring>(
      fullPath.filename().string(), ush::CodePage::UTF8);
  NTSTATUS subRes = addNtSearchData(
      info.currentSearchHandle,
      (fileName != L".")
          ? static_cast<PUNICODE_STRING>(UnicodeString(fileName.c_str()))
          : nullptr,
      virtualName, FileInformationClass, FileInformation, dataRead,
      info.foundFiles, nullptr, nullptr, nullptr, ReturnSingleEntry);
  if (subRes == STATUS_SUCCESS) {
    return true;
  } else {
    // STATUS_NO_MORE_FILES merely means the search ended, everything else is an
    // error message. Either way, the search here is finished and we should
    // resume in the next mapped directory
    if (subRes != STATUS_NO_MORE_FILES) {
      spdlog::get("hooks")->warn("error reported listing files in {0}: {1:x}",
                                 fullPath.string(),
                                 static_cast<uint32_t>(subRes));
    }
    return false;
  }
}

NTSTATUS WINAPI usvfs::hooks::NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
  // this is quite messy...
  // first, this will gather the virtual locations mapping to the iterated one
  // then we return results from the real location, skipping those that exist
  //   in the virtual locations, as those take precedence
  // finally the virtual results are returned, adding each result to a skip
  //   list, so they don't get added twice
  //
  // if we don't add the regular files first, "." and ".." wouldn't be in the
  //   first search result of wildcard searches which may confuse the caller
  NTSTATUS res = STATUS_NO_MORE_FILES;
  HOOK_START_GROUP(MutExHookGroup::FIND_FILES)
  if (!callContext.active()) {
    return ::NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                  IoStatusBlock, FileInformation, Length,
                                  FileInformationClass, ReturnSingleEntry,
                                  FileName, RestartScan);
  }

//  std::unique_lock<std::recursive_mutex> queryLock;
  std::map<HANDLE, Searches::Info>::iterator infoIter;
  bool firstSearch = false;

  { // scope to limit context lifetime
    HookContext::ConstPtr context = READ_CONTEXT();
    Searches &activeSearches = context->customData<Searches>(SearchInfo);
//    queryLock = std::unique_lock<std::recursive_mutex>(activeSearches.queryMutex);

    if (RestartScan) {
      auto iter = activeSearches.info.find(FileHandle);
      if (iter != activeSearches.info.end()) {
        activeSearches.info.erase(iter);
      }
    }

    // see if we already have a running search
    infoIter = activeSearches.info.find(FileHandle);
    firstSearch = (infoIter == activeSearches.info.end());
  }

  if (firstSearch) {
    HookContext::Ptr context = WRITE_CONTEXT();
    Searches &activeSearches = context->customData<Searches>(SearchInfo);
    // tradeoff time: we store this search status even if no virtual results
    // were found. This causes a little extra cost here and in NtClose every
    // time a non-virtual dir is being searched. However if we don't,
    // whenever NtQueryDirectoryFile is called another time on the same handle,
    // this (expensive) block would be run again.
    infoIter = activeSearches.info.insert(std::make_pair(FileHandle,
                                                         Searches::Info()))
                   .first;
    infoIter->second.searchPattern.appendPath(FileName);

    SearchHandleMap &searchMap
        = context->customData<SearchHandleMap>(SearchHandles);
    SearchHandleMap::iterator iter = searchMap.find(FileHandle);

    UnicodeString searchPath;
    if (iter != searchMap.end()) {
      searchPath = UnicodeString(iter->second.c_str());
      infoIter->second.currentSearchHandle =
          CreateFileW(iter->second.c_str(), GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    } else {
      searchPath = UnicodeString(FileHandle);
    }
    gatherVirtualEntries(searchPath, context->redirectionTable(), FileName,
                         infoIter->second);
  }

  ULONG dataRead = Length;
  PVOID FileInformationCurrent = FileInformation;

  // add regular search results, skipping those files we have in a virtual
  // location
  bool moreRegular  = !infoIter->second.regularComplete;
  bool dataReturned = false;
  while (moreRegular && !dataReturned) {
    dataRead        = Length;

    HANDLE handle = infoIter->second.currentSearchHandle;
    if (handle == INVALID_HANDLE_VALUE) {
      handle = FileHandle;
    }
    NTSTATUS subRes = addNtSearchData(
        handle, FileName, L"", FileInformationClass, FileInformationCurrent,
        dataRead, infoIter->second.foundFiles, Event, ApcRoutine, ApcContext,
        ReturnSingleEntry);
    moreRegular = subRes == STATUS_SUCCESS;
    if (moreRegular) {
      dataReturned = dataRead != 0;
    } else {
      infoIter->second.regularComplete = true;
      infoIter->second.foundFiles.clear();
      if (infoIter->second.currentSearchHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(infoIter->second.currentSearchHandle);
        infoIter->second.currentSearchHandle = INVALID_HANDLE_VALUE;
      }
    }
  }
  if (!moreRegular) {
    // add virtual results
    while (!dataReturned && infoIter->second.virtualMatches.size() > 0) {
      auto matchIter = infoIter->second.virtualMatches.rbegin();
      if (matchIter->realPath.size() != 0) {
        dataRead = Length;
        if (addVirtualSearchResult(FileInformationCurrent, FileInformationClass,
                                   infoIter->second, matchIter->realPath,
                                   matchIter->virtualName, ReturnSingleEntry,
                                   dataRead)) {
          // a positive result here means the call returned data and there may
          // be further objects to be retrieved by repeating the call
          dataReturned = true;
        } else {
          // proceed to next search handle

          // TODO: doesn't append search results from more than one redirection
          // per call. This is bad for performance but otherwise we'd need to
          // re-write the offsets between information objects
          infoIter->second.virtualMatches.pop_back();
          CloseHandle(infoIter->second.currentSearchHandle);
          infoIter->second.currentSearchHandle = INVALID_HANDLE_VALUE;
        }
      }
    }
  }

  if (!dataReturned) {
    if (firstSearch) {
      res = STATUS_NO_SUCH_FILE;
    } else {
      res = STATUS_NO_MORE_FILES;
    }
  } else {
    res = STATUS_SUCCESS;
  }
  IoStatusBlock->Status      = res;
  IoStatusBlock->Information = dataRead;

  size_t numVirtualFiles = infoIter->second.virtualMatches.size();
  if ((numVirtualFiles > 0)) {
    LOG_CALL()
        .addParam("path", UnicodeString(FileHandle))
        .PARAM(FileInformationClass)
        .PARAMWRAP(FileName)
        .PARAM(numVirtualFiles)
        .PARAMWRAP(res);
  }

  HOOK_END
  return res;
}

unique_ptr_deleter<OBJECT_ATTRIBUTES>
makeObjectAttributes(std::pair<UnicodeString, bool> &redirInfo,
                     POBJECT_ATTRIBUTES attributeTemplate)
{
  if (redirInfo.second) {
    unique_ptr_deleter<OBJECT_ATTRIBUTES> result(
        new OBJECT_ATTRIBUTES, [](OBJECT_ATTRIBUTES *ptr) { delete ptr; });
    memcpy(result.get(), attributeTemplate, sizeof(OBJECT_ATTRIBUTES));
    result->RootDirectory = nullptr;
    result->ObjectName    = static_cast<PUNICODE_STRING>(redirInfo.first);
    return result;
  } else {
    // just reuse the template with a dummy deleter
    return unique_ptr_deleter<OBJECT_ATTRIBUTES>(attributeTemplate,
                                                 [](OBJECT_ATTRIBUTES *) {});
  }
}

NTSTATUS WINAPI usvfs::hooks::NtOpenFile(PHANDLE FileHandle,
                                         ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes,
                                         PIO_STATUS_BLOCK IoStatusBlock,
                                         ULONG ShareAccess, ULONG OpenOptions)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;

  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)

  bool storePath = false;
  if (((OpenOptions & FILE_DIRECTORY_FILE) != 0UL)
      && ((OpenOptions & FILE_OPEN_FOR_BACKUP_INTENT) != 0UL)) {
    // this may be an attempt to open a directory handle for iterating.
    // If so we need to treat it a little bit differently
/*    usvfs::FunctionGroupLock lock(usvfs::MutExHookGroup::FILE_ATTRIBUTES);
    FILE_BASIC_INFORMATION dummy;
    storePath = FAILED(NtQueryAttributesFile(ObjectAttributes, &dummy));*/
    storePath = true;
  }

  UnicodeString fullName = CreateUnicodeString(ObjectAttributes);

  UnicodeString Path;
  Path.setFromHandle(ObjectAttributes->RootDirectory);

  std::wstring checkpath = ush::string_cast<std::wstring>(
    static_cast<LPCWSTR>(Path), ush::CodePage::UTF8);

  if ((fullName.size() == 0)
      || (GetFileSize(ObjectAttributes->RootDirectory, nullptr)
          != INVALID_FILE_SIZE)) {
	  //	//relative paths that we don't have permission over will fail here due that we can't get the filesize of the root directory
	  //	//We should try again to see if it is a directory using another method
	  if ((fullName.size() == 0) || (GetFileAttributesW((LPCWSTR)checkpath.c_str()) == INVALID_FILE_ATTRIBUTES)) {
          return ::NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                        IoStatusBlock, ShareAccess, OpenOptions);
	  }
  }

  try {
    std::pair<UnicodeString, bool> redir
        = applyReroute(READ_CONTEXT(), callContext, fullName);
    unique_ptr_deleter<OBJECT_ATTRIBUTES> adjustedAttributes
        = makeObjectAttributes(redir, ObjectAttributes);

    PRE_REALCALL
    res = ::NtOpenFile(FileHandle, DesiredAccess, adjustedAttributes.get(),
                       IoStatusBlock, ShareAccess, OpenOptions);
    POST_REALCALL
    if (SUCCEEDED(res) && storePath) {
      // store the original search path for use during iteration
      READ_CONTEXT()
          ->customData<SearchHandleMap>(SearchHandles)[*FileHandle]
          = static_cast<LPCWSTR>(fullName);
#pragma message("need to clean up this handle in CloseHandle call")
    }

    if (redir.second) {
      LOG_CALL()
          .addParam("source", ObjectAttributes)
          .addParam("rerouted", adjustedAttributes.get())
          .PARAM(*FileHandle)
          .PARAM(OpenOptions)
          .PARAMWRAP(res);
    }
  } catch (const std::exception&) {
    PRE_REALCALL
    res = ::NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                       IoStatusBlock, ShareAccess, OpenOptions);
    POST_REALCALL
  }
  HOOK_END

  return res;
}

bool fileExists(POBJECT_ATTRIBUTES attributes)
{
  UnicodeString temp = CreateUnicodeString(attributes);
  return RtlDoesFileExists_U(static_cast<PCWSTR>(temp)) == TRUE;
}

bool fileExists(const UnicodeString &filename)
{
  return RtlDoesFileExists_U(static_cast<PCWSTR>(filename)) == TRUE;
}

NTSTATUS WINAPI usvfs::hooks::NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
    ULONG EaLength)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;
  HOOK_START_GROUP(MutExHookGroup::OPEN_FILE)
  if (!callContext.active()) {
    return ::NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                          IoStatusBlock, AllocationSize, FileAttributes,
                          ShareAccess, CreateDisposition, CreateOptions,
                          EaBuffer, EaLength);
  }

  UnicodeString inPath = CreateUnicodeString(ObjectAttributes);

  if (inPath.size() == 0) {
    spdlog::get("hooks")->info(
        "failed to set from handle: {0}",
        ush::string_cast<std::string>(ObjectAttributes->ObjectName->Buffer));
    return ::NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                          IoStatusBlock, AllocationSize, FileAttributes,
                          ShareAccess, CreateDisposition, CreateOptions,
                          EaBuffer, EaLength);
  }

  std::pair<UnicodeString, bool> redir(UnicodeString(), false);

  { // limit context scope
    FunctionGroupLock lock(MutExHookGroup::ALL_GROUPS);
    HookContext::ConstPtr context = READ_CONTEXT();

    redir = applyReroute(context, callContext, inPath);

    // TODO would be neat if this could (optionally) reroute all potential write
    // accesses to the create target.
    //   This could be achived by copying the file to the target here in case
    //   the createdisposition or the requested access rights make that
    //   necessary
    if (((CreateDisposition == FILE_SUPERSEDE)
         || (CreateDisposition == FILE_CREATE)
         || (CreateDisposition == FILE_OPEN_IF)
         || (CreateDisposition == FILE_OVERWRITE_IF))
        && !redir.second && !fileExists(inPath)) {
      // the file will be created so now we need to know where
      std::pair<UnicodeString, UnicodeString> createTarget
          = findCreateTarget(context, inPath);

      if (createTarget.second.size() != 0) {
        // there is a reroute target for new files so adjust the path
        redir.first.resize(4);
        redir.first.appendPath(static_cast<PUNICODE_STRING>(createTarget.second));

        spdlog::get("hooks")->info(
            "reroute write access: {}",
            ush::string_cast<std::string>(static_cast<LPCWSTR>(redir.first))
                .c_str());
      }
    }
  }

  unique_ptr_deleter<OBJECT_ATTRIBUTES> adjustedAttributes
      = makeObjectAttributes(redir, ObjectAttributes);

  PRE_REALCALL
  res = ::NtCreateFile(FileHandle, DesiredAccess, adjustedAttributes.get(),
                       IoStatusBlock, AllocationSize, FileAttributes,
                       ShareAccess, CreateDisposition, CreateOptions, EaBuffer,
                       EaLength);
  POST_REALCALL

  if (redir.second) {
    LOG_CALL()
        .addParam("source", ObjectAttributes)
        .addParam("rerouted", adjustedAttributes.get())
        .PARAM(CreateDisposition)
        .PARAM(*FileHandle)
        .PARAMWRAP(res);
  }

  HOOK_END

  return res;
}

NTSTATUS WINAPI usvfs::hooks::NtClose(HANDLE Handle)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;

  HOOK_START_GROUP(MutExHookGroup::ALL_GROUPS)
  bool log = false;

  if ((::GetFileType(Handle) == FILE_TYPE_DISK)) {
    HookContext::Ptr context = WRITE_CONTEXT();

    { // clean up search data associated with this handle part 1
      Searches &activeSearches = context->customData<Searches>(SearchInfo);
//      std::lock_guard<std::recursive_mutex> lock(activeSearches.queryMutex);
      auto iter = activeSearches.info.find(Handle);
      if (iter != activeSearches.info.end()) {
        activeSearches.info.erase(iter);
        log = true;
      }
    }

    {
      SearchHandleMap &searchHandles
          = context->customData<SearchHandleMap>(SearchHandles);
      auto iter = searchHandles.find(Handle);
      if (iter != searchHandles.end()) {
        searchHandles.erase(iter);
        log = true;
      }
    }
  }

  PRE_REALCALL
  res = ::NtClose(Handle);
  POST_REALCALL

  if (log) {
    LOG_CALL().PARAM(Handle).PARAMWRAP(res);
  }

  HOOK_END

  return res;
}

NTSTATUS WINAPI usvfs::hooks::NtQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation)
{
  NTSTATUS res = STATUS_SUCCESS;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  UnicodeString inPath = CreateUnicodeString(ObjectAttributes);

  std::pair<UnicodeString, bool> redir
      = applyReroute(READ_CONTEXT(), callContext, inPath);
  unique_ptr_deleter<OBJECT_ATTRIBUTES> adjustedAttributes
      = makeObjectAttributes(redir, ObjectAttributes);

  PRE_REALCALL
  res = ::NtQueryAttributesFile(adjustedAttributes.get(), FileInformation);
  POST_REALCALL

  if (redir.second) {
    LOG_CALL()
        .addParam("source", ObjectAttributes)
        .addParam("rerouted", adjustedAttributes.get())
        .PARAMWRAP(res);
  }

  HOOK_END

  return res;
}

NTSTATUS WINAPI usvfs::hooks::NtQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
  NTSTATUS res = STATUS_SUCCESS;

  HOOK_START_GROUP(MutExHookGroup::FILE_ATTRIBUTES)

  if (!callContext.active()) {
    return ::NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
  }

  UnicodeString inPath;
  try {
    inPath = CreateUnicodeString(ObjectAttributes);
  } catch (const std::exception &) {
    return ::NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
  }

  std::pair<UnicodeString, bool> redir
      = applyReroute(READ_CONTEXT(), callContext, inPath);
  unique_ptr_deleter<OBJECT_ATTRIBUTES> adjustedAttributes
      = makeObjectAttributes(redir, ObjectAttributes);

  PRE_REALCALL
  res = ::NtQueryFullAttributesFile(adjustedAttributes.get(), FileInformation);
  POST_REALCALL

  if (redir.second) {
    LOG_CALL()
        .addParam("source", ObjectAttributes)
        .addParam("rerouted", adjustedAttributes.get())
        .PARAMWRAP(res);
  }

  HOOK_END

  return res;
}

NTSTATUS WINAPI usvfs::hooks::NtTerminateProcess(
  HANDLE ProcessHandle,
  NTSTATUS ExitStatus)
{
  NTSTATUS res = STATUS_SUCCESS;

  HOOK_START

  DisconnectVFS();

  res = ::NtTerminateProcess(ProcessHandle, ExitStatus);

  HOOK_END

  return res;
}
