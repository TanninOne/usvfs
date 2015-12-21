SET(testinject_bin_HDRS
	)

SET(testinject_bin_SRCS
	main.cpp
	)

ADD_EXECUTABLE(testinject_bin ${testinject_bin_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})
