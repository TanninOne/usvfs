PROJECT(shared)

SET(shared_HDRS
    addrtools.h
    logging.h
    windows_error.h
    debug_monitor.h
    shmlogger.h
    windows_sane.h
    directory_tree.h
    wildcard.h
    winapi.h
    shared_memory.h
    stringcast.h
    stringcast_basic.h
    stringcast_win.h
    stringutils.h
    scopeguard.h
    exceptionex.h
    ntdll_declarations.h
    unicodestring.h
	initguard.h
    )

SET(shared_SRCS
    addrtools.cpp
    logging.cpp
    windows_error.cpp
    debug_monitor.cpp
    shmlogger.cpp
    directory_tree.cpp
    wildcard.cpp
    winapi.cpp
    stringutils.cpp
    stringcast_win.cpp
    scopeguard.cpp
    exceptionex.cpp
    ntdll_declarations.cpp
    unicodestring.cpp
	initguard.cpp
    )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
                    )

ADD_DEFINITIONS(-DNOMINMAX)

ADD_LIBRARY(shared STATIC ${shared_HDRS} ${shared_SRCS})
#ADD_DEPENDENCIES(shared boost)
TARGET_LINK_LIBRARIES(shared)

IF (MSVC)
    SET_PROPERTY(TARGET shared APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /GS-")
ELSE()
    SET_PROPERTY(TARGET shared APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()
