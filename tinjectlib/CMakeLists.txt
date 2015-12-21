SET(tinjectlib_HDRS
    asmjit_sane.h
    injectlib.h
    )

SET(tinjectlib_SRCS
    injectlib.cpp
    )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${EP_PREFIX}/boost"
                    "${ASMJIT_SOURCE_DIR}/asmjit"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
 )

ADD_DEFINITIONS(-DNOMINMAX)

ADD_LIBRARY(tinjectlib STATIC ${tinjectlib_HDRS} ${tinjectlib_SRCS})

#ADD_DEPENDENCIES(tinjectlib asmjitext)
#ADD_DEPENDENCIES(tinjectlib boost)
#ADD_DEPENDENCIES(tinjectlib googletest)

TARGET_LINK_LIBRARIES(tinjectlib asmjit)

IF (MSVC)
    SET_PROPERTY(TARGET tinjectlib APPEND_STRING PROPERTY COMPILE_FLAGS "/W4")
ELSE()
    SET_PROPERTY(TARGET tinjectlib APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()
