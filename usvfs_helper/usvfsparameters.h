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

#include "../shared/logging.h"
#include "../usvfs/dllimport.h"


extern "C" {


struct USVFSParameters {
/*
  USVFSParameters()
    : debugMode(false)
    , logLevel(LogLevel::Debug)
  {
  }

  USVFSParameters(const char *instanceName, bool debugMode, LogLevel logLevel)
    : debugMode(debugMode)
    , logLevel(logLevel)
  {
    strncpy_s(this->instanceName, 64, instanceName, _TRUNCATE);
    strncpy_s(this->currentSHMName, 64, instanceName, _TRUNCATE);
  }

  USVFSParameters(const char *instanceName, const char *currentSHMName,
             bool debugMode, LogLevel logLevel)
    : debugMode(debugMode)
    , logLevel(logLevel)
  {
    strncpy_s(this->instanceName, 64, instanceName, _TRUNCATE);
    strncpy_s(this->currentSHMName, 64, currentSHMName, _TRUNCATE);
  }
*/
  char instanceName[65];
  char currentSHMName[65];
  bool debugMode{false};
  LogLevel logLevel{LogLevel::Debug};
};

}
