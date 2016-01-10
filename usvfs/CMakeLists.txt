SET(usvfs_HDRS
  dllimport.h
  hookcontext.h
  hookcallcontext.h
  hookmanager.h
  hooks/kernel32.h
  hooks/ntdll.h
  hooks/ole32.h
  hooks/cogetserverpid.h
  hooks/sharedids.h
  loghelpers.h
  redirectiontree.h
  semaphore.h
  stringcast_boost.h
  usvfs.h
  )

SET(usvfs_SRCS
  hookcontext.cpp
  hookcallcontext.cpp
  hookmanager.cpp
  hooks/kernel32.cpp
  hooks/ntdll.cpp
  hooks/ole32.cpp
  loghelpers.cpp
  redirectiontree.cpp
  semaphore.cpp
  stringcast_boost.cpp
  usvfs.cpp
  )

SET(usvfs_RCS
  version.rc
  )

SET_PROPERTY(
   SOURCE logger.cpp
   PROPERTY COMPILE_DEFINITIONS A DEFAULT_LOG_FILE=L"usvfs.log"
   )


INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/thooklib"
                    "${CMAKE_SOURCE_DIR}/tinjectlib"
                    "${CMAKE_SOURCE_DIR}/usvfs_helper"
                    "${ASMJIT_SOURCE_DIR}/AsmJit"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
                    )

MESSAGE(STATUS "linking against libs in ${CMAKE_BINARY_DIR}")

LINK_DIRECTORIES(${LINK_DIRECTORIES}
                 "${Boost_LIBRARY_DIRS}"
                 "${ASMJIT_BINARY_DIR}"
                 "${CMAKE_BINARY_DIR}/shared"
                 "${CMAKE_BINARY_DIR}/usvfs"
                 "${CMAKE_BINARY_DIR}/usvfs_helper"
                 "${UDIS86_BINARY_DIR}"
  )

ADD_DEFINITIONS(-D_WINDLL -DBOOST_LIB_DIAGNOSTIC -DNOMINMAX)

set(libname usvfs_${PROJ_ARCH})

ADD_LIBRARY(${libname} SHARED ${usvfs_HDRS} ${usvfs_SRCS} ${usvfs_RCS})
TARGET_LINK_LIBRARIES(${libname} asmjit shared libudis86 thooklib tinjectlib Shlwapi usvfs_helper)

IF (MSVC)
    SET_PROPERTY(TARGET ${libname} APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /wd4503 /GS-")
ELSE()
    SET_PROPERTY(TARGET ${libname} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()


SET_TARGET_PROPERTIES(${libname} PROPERTIES VERSION ${PROJ_VERSION})

###############
## Installation

INSTALL(TARGETS ${libname}
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION libs
)

INSTALL(FILES ${CMAKE_BINARY_DIR}/usvfs/${MY_CFG_INTDIR}/${libname}.pdb DESTINATION pdb)

