SET(thooklib_test_HDRS)

SET(thooklib_test_SRCS
    main.cpp
    )

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${ASMJIT_SOURCE_DIR}/asmjit"
                    "${GTEST_INCLUDE_DIR}"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/thooklib"
                    "${SPDLOG_INCLUDE_DIR}"
)

LINK_DIRECTORIES("${LINK_DIRECTORIES}"
                 "${CMAKE_BINARY_DIR}/shared"
                 "${ASMJIT_BINARY_DIR}"
                 "${UDIS86_BINARY_DIR}"
                 "${GTEST_LIBRARY_DIR}"
                 "${Boost_LIBRARY_DIRS}")

ADD_EXECUTABLE(thooklib_test ${thooklib_test_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})

#ADD_DEPENDENCIES(thooklib_test boost)
#ADD_DEPENDENCIES(thooklib_test googletest)

ADD_DEFINITIONS(-DASMJIT_STATIC)

TARGET_LINK_LIBRARIES(thooklib_test thooklib shared gtest.lib libudis86)

ADD_TEST(AllTestsForHooklib thooklib_test)

#SET_PROPERTY(TARGET thooklib_test APPEND_STRING PROPERTY COMPILE_DEFINITIONS "ASMJIT_STATIC")
SET_PROPERTY(TARGET thooklib_test APPEND PROPERTY COMPILE_DEFINITIONS "ASMJIT_STATIC")


#LIBS += -L../../gtest-build -lgtest -lgtest_main -L"$(BOOSTPATH)/stage/lib"
#LIBS += -L"$(UDIS86PATH)/build/release" -ludis86
