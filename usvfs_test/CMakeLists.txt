SET(usvfs_test_HDRS)

SET(usvfs_test_SRCS
    main.cpp
    )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${GTEST_INCLUDE_DIR}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/usvfs_helper"
                    "${CMAKE_SOURCE_DIR}/usvfs"
                    "${GTEST_INCLUDE_DIR}"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
)

LINK_DIRECTORIES(${LINK_DIRECTORIES}
                 "${CMAKE_BINARY_DIR}/shared"
                 "${CMAKE_BINARY_DIR}/usvfs"
                 "${ASMJIT_BINARY_DIR}"
                 "${GTEST_LIBRARY_DIR}"
                 "${Boost_LIBRARY_DIRS}"
                 "${UDIS86_BINARY_DIR}"
)

ADD_DEFINITIONS(-DUNITTEST)
REMOVE_DEFINITIONS(-DNDEBUG)

SET(libname usvfs_${PROJ_ARCH})
#IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
#    SET(libname usvfs_64)
#ENDIF()


ADD_EXECUTABLE(usvfs_test ${usvfs_test_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})

IF (MSVC)
    SET_PROPERTY(TARGET usvfs_test APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /wd4503 /GS-")
ELSE()
    SET_PROPERTY(TARGET usvfs_test APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()

#ADD_DEPENDENCIES(usvfs_test boost googletest)
ADD_DEPENDENCIES(usvfs_test ${libname})

TARGET_LINK_LIBRARIES(usvfs_test ${libname} shared gtest.lib)

ADD_CUSTOM_COMMAND(TARGET usvfs_test
                    POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/usvfs/${MY_CFG_INTDIR}/${libname}${POSTFIX}.dll ${CMAKE_BINARY_DIR}/usvfs_test/${MY_CFG_INTDIR})

ADD_TEST(AllTestsForUSVFS usvfs_test)
