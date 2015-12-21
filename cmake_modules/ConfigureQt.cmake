if(NOT DEFINED qt_dir)
  message(FATAL_ERROR "error: required variable qt_dir not defined...")
endif()

set(cmd configure.bat)
set(args "")

set(args ${args} -opensource -confirm-license -nomake tests -nomake examples)

set(result_value 0)

message(${cmd} ${args})

execute_process(COMMAND ${cmd} ${args}
  WORKING_DIRECTORY ${qt_dir}
  RESULT_VARIABLE result_value
)

if(NOT "${result_value}" STREQUAL "0")
  message(FATAL_ERROR "error: problem configuring Qt: rv='${rv}'")
endif()