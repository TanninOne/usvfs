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
#include "ntdll_declarations.h"
#include <cassert>

#define LOAD_EXT(mod, name) name = reinterpret_cast<name ## _type>(::GetProcAddress(mod, #name)); assert(name != nullptr)

NtQueryDirectoryFile_type NtQueryDirectoryFile;
NtQueryFullAttributesFile_type NtQueryFullAttributesFile;
NtQueryAttributesFile_type NtQueryAttributesFile;
NtOpenFile_type NtOpenFile;
NtCreateFile_type NtCreateFile;
NtClose_type NtClose;
RtlDoesFileExists_U_type RtlDoesFileExists_U;
RtlGetVersion_type RtlGetVersion;

static struct __Initializer {
  __Initializer() {
    HMODULE ntdllMod = ::LoadLibrary(TEXT("ntdll.dll"));

    if (ntdllMod == nullptr) {
      TerminateProcess(GetCurrentProcess(), 1);
      return;
    }
    LOAD_EXT(ntdllMod, NtQueryDirectoryFile);
    LOAD_EXT(ntdllMod, NtQueryFullAttributesFile);
    LOAD_EXT(ntdllMod, NtQueryAttributesFile);
    LOAD_EXT(ntdllMod, NtCreateFile);
    LOAD_EXT(ntdllMod, NtOpenFile);
    LOAD_EXT(ntdllMod, NtClose);
    LOAD_EXT(ntdllMod, RtlDoesFileExists_U);
    LOAD_EXT(ntdllMod, RtlGetVersion);
  }
} __initializer;
