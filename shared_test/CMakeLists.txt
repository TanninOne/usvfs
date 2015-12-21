SET(shared_test_HDRS )

SET(shared_test_SRCS
  main.cpp
  )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${GTEST_INCLUDE_DIR}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${GTEST_INCLUDE_DIR}"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
                    )
					
LINK_DIRECTORIES("${LINK_DIRECTORIES}"
                 "${CMAKE_BINARY_DIR}/shared"
                 "${Boost_LIBRARY_DIRS}"
                 )

ADD_EXECUTABLE(shared_test ${shared_test_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})

TARGET_LINK_LIBRARIES(shared_test gtest.lib shared)

#ADD_DEPENDENCIES(shared_test googletest)

IF (MSVC)
    SET_PROPERTY(TARGET shared_test APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /GS-")
ELSE()
    SET_PROPERTY(TARGET shared_test APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()


ADD_TEST(AllTestsForShared shared_test)
