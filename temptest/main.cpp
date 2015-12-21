#include <boost/filesystem.hpp>
#include <boost/chrono.hpp>
#include <Windows.h>
#include <cwctype>

using namespace boost::filesystem;
using namespace boost::chrono;


static const size_t TEST_ITERATIONS = 1000000;


LPCWSTR Relative(LPCWSTR string, LPCWSTR subString)
{
  std::locale loc;

  for (;;) {
    if (*subString == L'\0') {
      return string;
    } else if (*string == L'\0') {
      return nullptr;
    } else if (std::tolower(*string, loc) != std::tolower(*subString, loc)) {
      return nullptr;
    }
    ++string;
    ++subString;
  }
}

path::iterator Relative(const path &testPath, const path &subPath)
{
  path::iterator tIter = testPath.begin();
  path::iterator sIter = subPath.begin();

  for (;;) {
    if (sIter == subPath.end()) {
      return tIter;
    } else if (tIter == testPath.end()) {
      // testpath is shorter
      return testPath.end();
    } else if (*tIter != *sIter) {
      return testPath.end();
    }
    ++tIter;
    ++sIter;
  }
}

int main()
{
  std::wstring inPath = LR"(C:\temp\dies\ist\ein\test.txt)";
  std::wstring testPath = LR"(C:\temp)";
  path testP(testPath);
  std::wstring newBase = LR"(C:\bla)";
  path baseP(newBase);

   boost::chrono::system_clock::time_point start = boost::chrono::system_clock::now();

  for (int i = 0; i < TEST_ITERATIONS; ++i) {
    path p(inPath);
    path::iterator iter = Relative(p, testP);
    if (iter != p.end()) {
      path newPath = baseP;
      for (; iter != p.end(); ++iter) {
        newPath /= *iter;
      }
    } else {
      exit(1);
    }
  }

  boost::chrono::duration<double> sec = (boost::chrono::system_clock::now() - start);
  std::cout << "boost path: " << sec.count() << " second" << std::endl;

  start =  boost::chrono::system_clock::now();

  for (int i = 0; i < TEST_ITERATIONS; ++i) {
    LPCWSTR rel = Relative(inPath.c_str(), testPath.c_str());
    if (rel != nullptr) {
      std::wstring newPath = newBase + L"\\" + rel;
    } else {
      exit(1);
    }
  }

  sec = (boost::chrono::system_clock::now() - start);
  std::cout << "c string: " << sec.count() << " second" << std::endl;

  return 0;
}
