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

#include <string>
#include <boost/filesystem.hpp>


namespace usvfs {

namespace shared {

void strncpy_sz(char *dest, const char *src, size_t destSize);
void wcsncpy_sz(wchar_t *dest, const wchar_t *src, size_t destSize);

bool startswith(const wchar_t *string, const wchar_t *subString);


// Return path when appended to a_From will resolve to same as a_To
boost::filesystem::path make_relative(const boost::filesystem::path &from
                                      , const boost::filesystem::path &to);

std::string to_hex(void *bufferIn, size_t bufferSize);

} // namespace shared

} // namespace usvfs
