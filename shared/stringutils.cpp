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
#include "stringutils.h"
#include <cstring>
#include <iomanip>
#include <sstream>
#include <boost/algorithm/string/case_conv.hpp>
#include "windows_sane.h"
#include "windows_error.h"

#pragma warning ( disable : 4996 )


namespace bfs = boost::filesystem;


void usvfs::shared::strncpy_sz(char *dest, const char *src, size_t destSize)
{
  strncpy(dest, src, destSize - 1);
  dest[destSize - 1] = '\0';
}

void usvfs::shared::wcsncpy_sz(wchar_t *dest, const wchar_t *src, size_t destSize)
{
  wcsncpy(dest, src, destSize - 1);
  dest[destSize - 1] = L'\0';
}


bool usvfs::shared::startswith(const wchar_t *string, const wchar_t *subString)
{
  while ((*string != '\0') && (*subString != '\0')) {
    if (towlower(*string) != towlower(*subString)) {
      return false;
    }
    ++string;
    ++subString;
  }

  return *subString == '\0';
}

static bfs::path normalize(const bfs::path &path)
{
  bfs::path result;

  for (bfs::path::iterator iter = path.begin(); iter != path.end(); ++iter) {
    if (*iter == "..") {
      result = result.parent_path();
    } else if (*iter != ".") {
      result /= boost::to_lower_copy(iter->string());
    } // single dot is ignored
  }
  return result;
}

bfs::path usvfs::shared::make_relative(const bfs::path &fromIn,
                                       const bfs::path &toIn)
{
  // converting path to lower case to make iterator comparison work correctly
  // on case-insenstive filesystems
  bfs::path from(normalize(absolute(fromIn)));
  bfs::path to(  normalize(absolute(toIn)));

  // find common base
  bfs::path::const_iterator fromIter(from.begin());
  bfs::path::const_iterator toIter(to.begin());

  // TODO the following equivalent test is probably quite expensive as new
  // paths are created for each iteration but the case sensitivity depends on
  // the fs
  while ((fromIter != from.end())
         && (toIter != to.end())
         && (*fromIter == *toIter)) {
    ++fromIter;
    ++toIter;
  }

  // Navigate backwards in directory to reach previously found base
  boost::filesystem::path result;
  for (; fromIter != from.end(); ++fromIter) {
    if(*fromIter != ".") {
      result /= "..";
    }
  }

  // Now navigate down the directory branch
  for (; toIter != to.end(); ++toIter) {
    result /= *toIter;
  }
  return result;
}

std::string usvfs::shared::to_hex(void *bufferIn, size_t bufferSize)
{
  unsigned char *buffer = static_cast<unsigned char *>(bufferIn);
  std::ostringstream temp;
  temp << std::hex;
  for (size_t i = 0; i < bufferSize; ++i) {
    temp << std::setfill('0') << std::setw(2) << (unsigned int)buffer[i];
    if ((i % 16) == 15) {
      temp << "\n";
    } else {
      temp << " ";
    }
  }
  return temp.str();
}
