PROJECT(thooklib)

SET(thooklib_HDRS
    asmjit_sane.h
    utility.h
    hooklib.h
    udis86wrapper.h
    ttrampolinepool.h
    )

SET(thooklib_SRCS
    utility.cpp
    hooklib.cpp
    udis86wrapper.cpp
    ttrampolinepool.cpp
    )


INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${ASMJIT_SOURCE_DIR}/asmjit"
                    "${UDIS86_SOURCE_DIR}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${SPDLOG_INCLUDE_DIR}"
)

ADD_LIBRARY(thooklib STATIC ${thooklib_HDRS} ${thooklib_SRCS})
TARGET_LINK_LIBRARIES(thooklib shared asmjit)

#ADD_DEPENDENCIES(thooklib asmjitext)
#ADD_DEPENDENCIES(thooklib boost)
#ADD_DEPENDENCIES(thooklib googletest)

ADD_DEFINITIONS(-DASMJIT_STATIC)

IF (MSVC)
    SET_PROPERTY(TARGET thooklib APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /GS-")
ELSE()
    SET_PROPERTY(TARGET thooklib APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()

#SET_PROPERTY(TARGET thooklib APPEND_STRING PROPERTY COMPILE_DEFINITIONS "ASMJIT_STATIC")
SET_PROPERTY(TARGET thooklib APPEND PROPERTY COMPILE_DEFINITIONS "ASMJIT_STATIC;IDL=1")
