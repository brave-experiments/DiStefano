#Testing macro
macro (add_test_executable_with_lib _name libs)
	add_executable(test_${_name} "${_name}.cpp")
	target_link_libraries(test_${_name} ${EMP-OT_LIBRARIES})
endmacro()

macro (add_test_case _name)
	add_test_executable_with_lib(${_name} "")
  	add_test(NAME ${_name} COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")
endmacro()

macro (add_test_case_with_run _name)
	add_test_executable_with_lib(${_name} "")
	add_test(NAME ${_name} COMMAND "./run" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")

endmacro()

# Test cases
add_test_case_with_run(aes)
add_test_case_with_run(sha1)
add_test_case_with_run(sha256)
add_test_case_with_run(simple_circuit)
add_test_case_with_run(abit)
add_test_case_with_run(triple)
add_test_case_with_run(amortized_2pc)
add_test_case_with_run(aes_mult_inputs)
