#CMAKE_POLICY(SET CMP0043 OLD)

SET (usvfs_loader_HDRS
    )

SET(usvfs_loader_SRCS
    main.cpp
    )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
SET(CMAKE_AUTOMOC OFF)

FIND_PACKAGE(Qt5Widgets)

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${CMAKE_SOURCE_DIR}/tinjectlib"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/usvfs"
                    "${CMAKE_SOURCE_DIR}/usvfs_helper"
                    "${ASMJIT_SOURCE_DIR}/AsmJit"
                    "${GTEST_INCLUDE_DIR}"
                    "${SPDLOG_INCLUDE_DIR}"
                    "${CPPFORMAT_SOURCE_DIR}"
)

LINK_DIRECTORIES(${LINK_DIRECTORIES}
                 "${Boost_LIBRARY_DIRS}"
                 "${ASMJIT_BINARY_DIR}"
                 "${CMAKE_BINARY_DIR}/shared"
                 "${UDIS86_BINARY_DIR}"
                 "${CMAKE_BINARY_DIR}/usvfs"
                 "${CMAKE_BINARY_DIR}/usvfs_helper"
    )


SET(libname usvfs_${PROJ_ARCH})
SET(exename usvfs_loader)
#if(CMAKE_SIZEOF_VOID_P EQUAL 8)
#  set(libname usvfs_64)
#  SET(exename usvfs_loader_64)
#endif()


ADD_EXECUTABLE(${exename} ${usvfs_loader_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})
TARGET_LINK_LIBRARIES(${exename} asmjit shared tinjectlib usvfs_helper ${libname})

ADD_DEPENDENCIES(${exename} ${libname})

# Use the Widgets module from Qt 5.
QT5_USE_MODULES(${exename} Widgets)

IF (MSVC)
    SET_PROPERTY(TARGET ${exename} APPEND PROPERTY COMPILE_FLAGS "/W4 /wd4503 /GS-")
    # SET_PROPERTY(TARGET ${exename} APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /wd4503 /GS-")
ELSE()
    SET_PROPERTY(TARGET ${exename} APPEND PROPERTY COMPILE_FLAGS "-Wall")
    # SET_PROPERTY(TARGET ${exename} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()


SET_TARGET_PROPERTIES(${exename} PROPERTIES VERSION ${PROJ_VERSION})

###############
## Installation

INSTALL(TARGETS ${exename}
  RUNTIME DESTINATION bin_${PROJ_ARCH}
)

INSTALL(FILES ${CMAKE_BINARY_DIR}/usvfs_loader/${MY_CFG_INTDIR}/${exename}.pdb DESTINATION bin_${PROJ_ARCH})
