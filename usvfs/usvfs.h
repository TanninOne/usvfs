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
#pragma once

#include "dllimport.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../usvfs_helper/usvfsparameters.h"


/*
 * Virtual operations:
 *   - link file
 *   - link directory (empty)
 *   - link directory (static)
 *   - link directory (dynamic)
 *   - delete file
 *   - delete directory
 * Maybe:
 *   - rename/move (= copy + delete)
 *   - copy-on-write semantics (changes to files are done in a separate copy of the file, the original is kept on disc but hidden)
 */


static const unsigned int LINKFLAG_FAILIFEXISTS   = 0x00000001; // if set, linking fails in case of an error
static const unsigned int LINKFLAG_MONITORCHANGES = 0x00000002; // if set, changes to the source directory after the link operation
                                                                // will be updated in the virtual fs. only relevant in static
                                                                // link directory operations
static const unsigned int LINKFLAG_CREATETARGET   = 0x00000004; // if set, file creation (including move or copy) operations to
                                                                // destination will be redirected to the source. Only one createtarget
                                                                // can be set for a destination folder so this flag will replace
                                                                // the previous create target.
                                                                // If there different create-target have been set for an element and one of its
                                                                // ancestors, the inner-most create-target is used
static const unsigned int LINKFLAG_RECURSIVE      = 0x00000008; // if set, directories are linked recursively


extern "C" {

/**
 * removes all virtual mappings
 */
DLLEXPORT void WINAPI ClearVirtualMappings();

/**
 * link a file virtually
 * @note: the directory the destination file resides in has to exist - at least virtually.
 */
DLLEXPORT BOOL WINAPI VirtualLinkFile(LPCWSTR source, LPCWSTR destination, unsigned int flags);

/**
 * link a directory virtually. This static variant recursively links all files individually, change notifications
 * are used to update the information.
 * @param failIfExists if true, this call fails if the destination directory exists (virtually or physically)
 */
DLLEXPORT BOOL WINAPI VirtualLinkDirectoryStatic(LPCWSTR source, LPCWSTR destination, unsigned int flags);

/**
 * connect to a virtual filesystem as a controller, without hooking the calling process. Please note that
 * you can only be connected to one vfs, so this will silently disconnect from a previous vfs.
 */
DLLEXPORT BOOL WINAPI ConnectVFS(const USVFSParameters *parameters);

/**
 * @brief create a new VFS. This is similar to ConnectVFS except it guarantees
 *   the vfs is reset before use.
 */
DLLEXPORT BOOL WINAPI CreateVFS(const USVFSParameters *parameters);

/**
 * disconnect from a virtual filesystem. This removes hooks if necessary
 */
DLLEXPORT void WINAPI DisconnectVFS();

DLLEXPORT void WINAPI GetCurrentVFSName(char *buffer, size_t size);

/**
 * retrieve a list of all processes connected to the vfs
 */
DLLEXPORT BOOL WINAPI GetVFSProcessList(size_t *count, LPDWORD processIDs);

/**
 * spawn a new process that can see the virtual file system. The signature is identical to CreateProcess
 */
DLLEXPORT BOOL WINAPI CreateProcessHooked(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

/**
 * retrieve a single log message.
 * FIXME There is currently no way to unblock from the caller side
 * FIXME retrieves log messages from all instances, the logging queue is not separated
 */
DLLEXPORT bool WINAPI GetLogMessages(LPSTR buffer, size_t size, bool blocking = false);

/**
 * @brief Used to change parameters which can be changed in runtime
 */
DLLEXPORT void WINAPI USVFSUpdateParams(LogLevel level, CrashDumpsType type);

/**
 * retrieves a readable representation of the vfs tree
 * @param buffer the buffer to write to. this may be null if you only want to determine the required
 *               buffer size
 * @param size   pointer to a variable that contains the buffer. After the call
 *               this value will have been updated to contain the required size,
 *               even if this is bigger than the buffer size
 */
DLLEXPORT BOOL WINAPI CreateVFSDump(LPSTR buffer, size_t *size);

/**
 * adds an executable to the blacklist so it doesn't get exposed to the virtual
 * file system
 * @param executableName  name of the executable
 */
DLLEXPORT VOID WINAPI BlacklistExecutable(LPWSTR executableName);

/**
 * print debugging info about the vfs. The format is currently not fixed and may
 * change between usvfs versions
 */
DLLEXPORT VOID WINAPI PrintDebugInfo();

//#if defined(UNITTEST) || defined(_WINDLL)
DLLEXPORT void WINAPI InitLogging(bool toLocal = false);
//#endif

/**
 * used internally to initialize a process at startup-time as a "slave". Don't call directly
 */
DLLEXPORT void __cdecl InitHooks(LPVOID userData, size_t userDataSize);


DLLEXPORT void WINAPI USVFSInitParameters(USVFSParameters *parameters,
                                          const char *instanceName,
                                          bool debugMode,
                                          LogLevel logLevel,
                                          CrashDumpsType crashDumpsType,
                                          const char *crashDumpsPath);

}
