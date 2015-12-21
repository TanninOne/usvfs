SET(testinject_dll_HDRS
	main.h
	)

SET(testinject_dll_SRCS
	main.cpp
	)

ADD_LIBRARY(testinject_dll SHARED ${testinject_dll_SRCS} ${UIS} ${RSCS} ${TRS} ${MOCS})
