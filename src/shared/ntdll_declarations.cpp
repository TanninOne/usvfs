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
NtTerminateProcess_type NtTerminateProcess;


static struct __Initializer {
  HMODULE m_NtDLLMod;
  __Initializer() {
    m_NtDLLMod = ::LoadLibrary(TEXT("ntdll.dll"));

    if (m_NtDLLMod == nullptr) {
      TerminateProcess(GetCurrentProcess(), 1);
      return;
    }
    LOAD_EXT(m_NtDLLMod, NtQueryDirectoryFile);
    LOAD_EXT(m_NtDLLMod, NtQueryFullAttributesFile);
    LOAD_EXT(m_NtDLLMod, NtQueryAttributesFile);
    LOAD_EXT(m_NtDLLMod, NtCreateFile);
    LOAD_EXT(m_NtDLLMod, NtOpenFile);
    LOAD_EXT(m_NtDLLMod, NtClose);
    LOAD_EXT(m_NtDLLMod, RtlDoesFileExists_U);
    LOAD_EXT(m_NtDLLMod, RtlGetVersion);
    LOAD_EXT(m_NtDLLMod, NtTerminateProcess);
  }

  ~__Initializer() {
    // all hooks should be disabled by now. If not, this won't end well...
    FreeLibrary(m_NtDLLMod);
  }
} __initializer;
