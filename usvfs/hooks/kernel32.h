#pragma once

#include "ntdll_declarations.h"
#include <windows_sane.h>
#include "../dllimport.h"

namespace usvfs {

namespace hooks {

DLLEXPORT HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

DLLEXPORT BOOL WINAPI GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
DLLEXPORT DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
DLLEXPORT DWORD WINAPI SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);

DLLEXPORT DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
DLLEXPORT BOOL WINAPI SetCurrentDirectoryW(LPCWSTR lpPathName);
DLLEXPORT DWORD WINAPI GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);

DLLEXPORT HMODULE WINAPI LoadLibraryExW(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags);
DLLEXPORT HMODULE WINAPI LoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags);
DLLEXPORT HMODULE WINAPI LoadLibraryW(LPCWSTR lpFileName);
DLLEXPORT HMODULE WINAPI LoadLibraryA(LPCSTR lpFileName);

DLLEXPORT BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DLLEXPORT BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

DLLEXPORT DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

DLLEXPORT VOID WINAPI ExitProcess(UINT exitCode);

}

}
