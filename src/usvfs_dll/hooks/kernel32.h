#pragma once

#include "ntdll_declarations.h"
#include <windows_sane.h>
#include <dllimport.h>

namespace usvfs {

DLLEXPORT HANDLE WINAPI hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DLLEXPORT HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DLLEXPORT HANDLE WINAPI hook_CreateFile2(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams);

DLLEXPORT BOOL WINAPI hook_GetFileAttributesExA(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
DLLEXPORT BOOL WINAPI hook_GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
DLLEXPORT DWORD WINAPI hook_GetFileAttributesA(LPCSTR lpFileName);
DLLEXPORT DWORD WINAPI hook_GetFileAttributesW(LPCWSTR lpFileName);
DLLEXPORT DWORD WINAPI hook_SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);

DLLEXPORT DWORD WINAPI hook_GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer);
DLLEXPORT DWORD WINAPI hook_GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
DLLEXPORT BOOL WINAPI hook_SetCurrentDirectoryA(LPCSTR lpPathName);
DLLEXPORT BOOL WINAPI hook_SetCurrentDirectoryW(LPCWSTR lpPathName);
DLLEXPORT DWORD WINAPI hook_GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);

DLLEXPORT BOOL WINAPI hook_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DLLEXPORT BOOL WINAPI hook_RemoveDirectoryW(LPCWSTR lpPathName);

DLLEXPORT BOOL WINAPI hook_DeleteFileW(LPCWSTR lpFileName);
DLLEXPORT BOOL WINAPI hook_DeleteFileA(LPCSTR lpFileName);

DLLEXPORT BOOL WINAPI hook_MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);
DLLEXPORT BOOL WINAPI hook_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
DLLEXPORT BOOL WINAPI hook_MoveFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags);
DLLEXPORT BOOL WINAPI hook_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags);

DLLEXPORT BOOL WINAPI hook_CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
DLLEXPORT BOOL WINAPI hook_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);
DLLEXPORT BOOL WINAPI hook_CopyFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags);
DLLEXPORT BOOL WINAPI hook_CopyFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags);
DLLEXPORT HRESULT WINAPI hook_CopyFile2(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters);

DLLEXPORT HMODULE WINAPI hook_LoadLibraryExW(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags);
DLLEXPORT HMODULE WINAPI hook_LoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags);
DLLEXPORT HMODULE WINAPI hook_LoadLibraryW(LPCWSTR lpFileName);
DLLEXPORT HMODULE WINAPI hook_LoadLibraryA(LPCSTR lpFileName);

DLLEXPORT BOOL WINAPI hook_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DLLEXPORT BOOL WINAPI hook_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

DLLEXPORT DWORD WINAPI hook_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
DLLEXPORT DWORD WINAPI hook_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

DLLEXPORT BOOL WINAPI hook_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DLLEXPORT BOOL WINAPI hook_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);

DLLEXPORT DWORD WINAPI hook_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
DLLEXPORT DWORD WINAPI hook_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lptstrFilename, LPDWORD lpdwHandle);

DLLEXPORT HANDLE WINAPI hook_FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
DLLEXPORT HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

DLLEXPORT DWORD WINAPI hook_GetPrivateProfileSectionNamesA(LPSTR lpszReturnBuffer, DWORD nSize, LPCSTR lpFileName);
DLLEXPORT DWORD WINAPI hook_GetPrivateProfileSectionNamesW(LPWSTR lpszReturnBuffer, DWORD nSize, LPCWSTR lpFileName);
DLLEXPORT DWORD WINAPI hook_GetPrivateProfileSectionA(LPCSTR lpAppName, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName);
DLLEXPORT DWORD WINAPI hook_GetPrivateProfileSectionW(LPCWSTR lpAppName, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName);
DLLEXPORT BOOL WINAPI hook_WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName);
DLLEXPORT BOOL WINAPI hook_WritePrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpString, LPCWSTR lpFileName);

DLLEXPORT VOID WINAPI hook_ExitProcess(UINT exitCode);

}
