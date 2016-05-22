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
#include <string>
#include <limits>
#include <boost/type_traits.hpp>
#include <boost/static_assert.hpp>

namespace usvfs {
namespace shared {

enum class CodePage {
  LOCAL,
  LATIN1,
  UTF8
};

template <typename ToT, typename FromT>
class string_cast_impl {
public:
  static ToT cast(const FromT &source, CodePage codePage, size_t sourceLength);
};

template <typename ToT, typename FromT>
ToT string_cast(FromT source
                , CodePage codePage = CodePage::LOCAL
                , size_t sourceLength = std::numeric_limits<size_t>::max())
{
  return string_cast_impl<ToT, FromT>::cast(source, codePage, sourceLength);
}


template <typename ToT, typename CharT>
class string_cast_impl<ToT, std::basic_string<CharT>> {
public:
  static ToT cast(const std::basic_string<CharT> &source, CodePage codePage, size_t sourceLength)
  {
    return string_cast_impl<ToT, const CharT*>::cast(source.c_str(), codePage, sourceLength);
  }
};

template <typename ToT, typename CharT>
class string_cast_impl<ToT, CharT*> {
  BOOST_STATIC_ASSERT(!boost::is_base_and_derived<ToT, CharT>::value);
public:
  static ToT cast(CharT *source, CodePage codePage, size_t sourceLength)
  {
    return string_cast_impl<ToT, const CharT*>::cast(source, codePage, sourceLength);
  }
};


template <typename ToT, typename CharT, int N>
class string_cast_impl<ToT, CharT[N]> {
public:
  static ToT cast(CharT(&source)[N], CodePage codePage, size_t sourceLength)
  {
    return string_cast_impl<ToT, const CharT*>::cast(source, codePage, sourceLength);
  }
};

}
}
