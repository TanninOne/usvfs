SET(temptest_HDRS )

SET(temptest_SRCS
	main.cpp
	)

#INCLUDE_DIRECTORIES("${BoostLibDir}")

LINK_DIRECTORIES(${LINK_DIRECTORIES}
								 "${BoostLibDir}")

ADD_EXECUTABLE(temptest ${temptest_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})

#TARGET_LINK_LIBRARIES(temptest)
