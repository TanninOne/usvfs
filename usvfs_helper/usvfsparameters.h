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

#include "../shared/stringutils.h"
#include "../shared/logging.h"
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/set.hpp>
#include "../shared/shared_memory.h"

namespace usvfs
{

struct Parameters {

  Parameters()
    : debugMode(false)
    , logLevel(LogLevel::Debug)
  {
  }

  Parameters(const char *instanceName, bool debugMode, LogLevel logLevel)
    : debugMode(debugMode)
    , logLevel(logLevel)
  {
    strncpy_s(this->instanceName, 64, instanceName, _TRUNCATE);
    strncpy_s(this->currentSHMName, 64, instanceName, _TRUNCATE);
  }

  Parameters(const char *instanceName, const char *currentSHMName,
             bool debugMode, LogLevel logLevel)
    : debugMode(debugMode)
    , logLevel(logLevel)
  {
    strncpy_s(this->instanceName, 64, instanceName, _TRUNCATE);
    strncpy_s(this->currentSHMName, 64, currentSHMName, _TRUNCATE);
  }

  char instanceName[65];
  char currentSHMName[65];
  bool debugMode{false};
  LogLevel logLevel{LogLevel::Debug};
};

typedef shared::VoidAllocatorT::rebind<DWORD>::other DWORDAllocatorT;
typedef shared::VoidAllocatorT::rebind<shared::StringT>::other StringAllocatorT;

__declspec(align(8)) struct SharedParameters {

  SharedParameters() = delete;

  SharedParameters(const SharedParameters &reference) = delete;

  SharedParameters &operator=(const SharedParameters &reference) = delete;

  SharedParameters(const Parameters &reference,
                   const shared::VoidAllocatorT &allocator)
    : instanceName(reference.instanceName, allocator)
    , currentSHMName(reference.currentSHMName, allocator)
    , debugMode(reference.debugMode)
    , logLevel(reference.logLevel)
    , userCount(1)
    , processBlacklist(allocator)
    , processList(allocator)
  {
  }

  explicit operator Parameters()
  {
    Parameters result(instanceName.c_str(), currentSHMName.c_str(), debugMode,
                      logLevel);
    return result;
  }

  shared::StringT instanceName;
  shared::StringT currentSHMName;
  bool debugMode;
  LogLevel logLevel;
  uint32_t userCount;
  boost::container::set<shared::StringT, std::less<shared::StringT>,
                        StringAllocatorT> processBlacklist;
  boost::container::set<DWORD, std::less<DWORD>, DWORDAllocatorT> processList;
};
}
