SET(tinjectlib_test_HDRS )

SET(tinjectlib_test_SRCS
    main.cpp
    )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${GTEST_INCLUDE_DIR}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/tinjectlib"
                    "${SPDLOG_INCLUDE_DIR}"
                    )

LINK_DIRECTORIES(${LINK_DIRECTORIES}
                 "${CMAKE_BINARY_DIR}/shared"
                 "${ASMJIT_BINARY_DIR}"
                 "${GTEST_LIBRARY_DIR}"
                 "${Boost_LIBRARY_DIRS}"
)

ADD_EXECUTABLE(tinjectlib_test ${tinjectlib_test_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})

TARGET_LINK_LIBRARIES(tinjectlib_test tinjectlib gtest.lib shared)

ADD_DEPENDENCIES(tinjectlib_test testinject_bin testinject_dll)

ADD_CUSTOM_COMMAND(TARGET tinjectlib_test
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/testinject_bin/${MY_CFG_INTDIR}/testinject_bin.exe ${CMAKE_BINARY_DIR}/tinjectlib_test/${MY_CFG_INTDIR}
                   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/testinject_dll/${MY_CFG_INTDIR}/testinject_dll${POSTFIX}.dll ${CMAKE_BINARY_DIR}/tinjectlib_test/${MY_CFG_INTDIR})


ADD_TEST(AllTestsForInjectlib tinjectlib_test)


