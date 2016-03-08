SET (usvfs_proxy_HDRS
    )

SET(usvfs_proxy_SRCS
    main.cpp
    )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
SET(CMAKE_AUTOMOC OFF)

INCLUDE_DIRECTORIES("${Boost_INCLUDE_DIRS}"
                    "${CMAKE_SOURCE_DIR}/tinjectlib"
                    "${CMAKE_SOURCE_DIR}/shared"
                    "${CMAKE_SOURCE_DIR}/usvfs"
                    "${CMAKE_SOURCE_DIR}/usvfs_helper"
                    "${ASMJIT_SOURCE_DIR}/AsmJit"
                    "${SPDLOG_INCLUDE_DIR}"
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
SET(exename usvfs_proxy)

ADD_EXECUTABLE(${exename} ${usvfs_proxy_SRCS} ${UIS} ${RSCS})
TARGET_LINK_LIBRARIES(${exename} asmjit shared tinjectlib usvfs_helper ${libname})

ADD_DEPENDENCIES(${exename} ${libname})

IF (MSVC)
    SET_PROPERTY(TARGET ${exename} APPEND_STRING PROPERTY COMPILE_FLAGS "/W4 /wd4503 /GS-")
ELSE()
    SET_PROPERTY(TARGET ${exename} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall")
ENDIF()

SET_TARGET_PROPERTIES(${exename} PROPERTIES VERSION ${PROJ_VERSION})

###############
## Installation

INSTALL(TARGETS ${exename}
  RUNTIME DESTINATION bin_${PROJ_ARCH}
)

INSTALL(FILES ${CMAKE_BINARY_DIR}/usvfs_proxy/${MY_CFG_INTDIR}/${exename}.pdb DESTINATION pdb)
