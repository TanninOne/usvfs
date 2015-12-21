# do not set warning level build-wide, we want the power to control warnings per-target
STRING(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

IF(CMAKE_BUILD_TYPE STREQUAL "")
  SET(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: None (CMAKE_CXX_FLAGS or CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF()
MESSAGE(STATUS "build type ${CMAKE_BUILD_TYPE}")

SET(CMAKE_DEBUG_POSTFIX -d)
SET(CMAKE_VERBOSE_MAKEFILE CACHE BOOL ON)

IF(CMAKE_BUILD_TYPE MATCHES Debug)
  SET(POSTFIX ${CMAKE_DEBUG_POSTFIX})
  ADD_DEFINITIONS(-DDEBUG)
ELSE(CMAKE_BUILD_TYPE MATCHES Debug)
  SET(POSTFIX ${CMAKE_RELEASE_POSTFIX})
ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)

if (MSVC)
ELSE()
  ADD_DEFINITIONS(-D_WIN32_WINNT=0x600 -DWIN32 -D_WIN32 -D__cplusplus=201103L)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-unknown-pragmas -Wno-unused-variable")
ENDIF()

#FOREACH(flag_var CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_MINSIZEREL)
#  IF(${flag_var} MATCHES "/MD")
#    STRING(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
#  ENDIF(${flag_var} MATCHES "/MD")
#ENDFOREACH(flag_var)

# build systems that support multiple configurations in one build script (i.e. vs solutions) may use
# a subdirectory below each component to separate configurations. This path is available at build-time
# through ${CMAKE_CFG_INTDIR} but not at configuration time (which affects installations) so try
# to predict the path here
IF(${CMAKE_CFG_INTDIR} STREQUAL ".")
  SET(MY_CFG_INTDIR ".")
ELSE()
  SET(MY_CFG_INTDIR "${CMAKE_BUILD_TYPE}")
ENDIF()

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake_modules)

INCLUDE(TargetArch)
INCLUDE(Utils)
INCLUDE(ExternalProject)
# make external projects download to third_party subdirectory
SET(EXTERNAL_PROJECT_DIRECTORY ${CMAKE_BINARY_DIR}/third_party)
SET_DIRECTORY_PROPERTIES(PROPERTIES EP_PREFIX ${EXTERNAL_PROJECT_DIRECTORY})

# adding boost. requires some preparation
TARGET_ARCHITECTURE(TargetArchitecture)

# the boost script sets its output variables to parent scope so we have to run it in a
# scope for it to work
#FUNCTION(include_subscope)
#  INCLUDE(AddBoost)
#ENDFUNCTION(include_subscope)

#INCLUDE_SUBSCOPE()
#INCLUDE(AddGTest)
#INCLUDE(AddAsmJit)
#INCLUDE(AddUdis86)
#INCLUDE(AddSpdlog)
#INCLUDE(AddCppFormat)
#INCLUDE(AddQt)

LIST(APPEND CMAKE_PREFIX_PATH ${DEPENDENCIES_DIR}/qt5/lib/cmake)

SET(DEPENDENCIES_DIR CACHE PATH "")

# hint to find qt in dependencies path
FILE(GLOB_RECURSE BOOST_ROOT ${DEPENDENCIES_DIR}/boost*/project-config.jam)
GET_FILENAME_COMPONENT(BOOST_ROOT ${BOOST_ROOT} DIRECTORY)

#hint to find boost in dependencies path
FILE(GLOB_RECURSE BOOST_ROOT ${DEPENDENCIES_DIR}/boost*/project-config.jam)
GET_FILENAME_COMPONENT(BOOST_ROOT ${BOOST_ROOT} DIRECTORY)
FIND_PACKAGE(Qt5Widgets REQUIRED)
FIND_PACKAGE(Boost REQUIRED)
FIND_PACKAGE(Spdlog REQUIRED)
FIND_PACKAGE(CppFormat REQUIRED)
FIND_PACKAGE(GTest REQUIRED)
FIND_PACKAGE(AsmJit REQUIRED)
FIND_PACKAGE(Udis86 REQUIRED)


#SET(Subversion_SVN_EXECUTABLE CACHE FILEPATH "C:/Program Files/SlikSvn/bin/svn.exe")
#SET(QTDIR CACHE FILEPATH "C:/QtSDK5/Qt5.4.0/5.4/msvc2013_opengl")
