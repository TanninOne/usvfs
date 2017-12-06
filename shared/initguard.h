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

#include <atomic>

namespace usvfs {

namespace shared {

// InitGuard is aimed to be a proper guard meaning one day it might actually
// guarantee that if you create an InitGuard object and it is true, then any
// deinitialize request (in a different thread) will be delayed until the
// InitGuard object reaches the end of its life.
// For now its more of an init flag and just checks if deinitialize has not
// been called yet.
class InitGuard {
public:
	operator bool() { return _initialized; }

	static void initialize();
	static void deinitialize();

private:
	static std::atomic<bool> _initialized;
};

} // namespace shared

} // namespace usvfs
