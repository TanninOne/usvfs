SET(usvfs_helper_HDRS
    inject.h
    usvfsparameters.h
    )

SET(usvfs_helper_SRCS
    inject.cpp
    usvfsparameters.cpp
    )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/tinjectlib"
                    "${CMAKE_SOURCE_DIR}/usvfs"
                    "${SPDLOG_INCLUDE_DIR}"
    )

LINK_DIRECTORIES(
    )

ADD_DEFINITIONS(-D_WINDLL -DNOMINMAX)


ADD_LIBRARY(usvfs_helper STATIC ${usvfs_helper_HDRS} ${usvfs_helper_SRCS})
TARGET_LINK_LIBRARIES(usvfs_helper)

IF (MSVC)
    SET_PROPERTY(TARGET usvfs_helper APPEND_STRING PROPERTY COMPILE_FLAGS "/W4")
ELSE()
    SET_PROPERTY(TARGET usvfs_helper APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()
