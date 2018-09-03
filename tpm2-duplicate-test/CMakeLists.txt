cmake_minimum_required(VERSION 3.5.1)
project(TPM2_0_TSS_TEST)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
add_definitions(-DMAXLOGLEVEL=6)


set(COMM_SOURCE_FILES
		./main.c
		./sapi-util.c
		./context-util.c
        ./test-options.c
	    ./log/log.c
        )

set(LIB_FILES
		lib/files.c
		lib/log.c
		lib/pcr.c
		lib/tpm2_alg_util.c
		lib/tpm2_attr_util.c
		lib/tpm2_convert.c
		lib/tpm2_ctx_mgmt.c
		lib/tpm2_errata.c
		lib/tpm2_error.c
		lib/tpm2_hash.c
		lib/tpm2_hierarchy.c
		lib/tpm2_openssl.c
		lib/tpm2_options.c
		lib/tpm2_password_util.c
		lib/tpm2_policy.c
		lib/tpm2_session.c
		lib/tpm2_tcti_ldr.c
		lib/tpm2_util.c
		lib/tpm_kdfa.c
		)

set(TOOL_PORT_FILES
		tools_port/tpm2_createek.c
		tools_port/tpm2_createak.c
		tools_port/tpm2_createprimary.c
		tools_port/tpm2_create.c
		tools_port/tpm2_createpolicy.c
		tools_port/tpm2_duplicate.c
		)


set(TEST_CASE
        ./duplicate-test.c
        )


LINK_LIBRARIES(
	    libcrypto.so
        libmarshal.so
        libsapi.so
		libssl.so
		libtcti-device.so
        libtcti-socket.so
        liburiparser.so
)


INCLUDE_DIRECTORIES(
		.
		./log
		./lib
		./tools_port
		./tools
	    /usr/local/include
        /usr/lib64
)

LINK_DIRECTORIES(
		.
		/usr/local/lib
)

add_library(comm STATIC ${LIB_FILES})
add_executable(duplicate-test ${COMM_SOURCE_FILES} ${TOOL_PORT_FILES} ${TEST_CASE})
target_link_libraries(duplicate-test comm)

#SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin_test_int)
#MESSAGE(${EXECUTABLE_OUTPUT_PATH})
#
#FOREACH (test_case ${TEST_CASES})
#    MESSAGE(${test_case})
#    string(REGEX REPLACE ".*/" "test_int." Exe ${test_case})
#    string(REGEX REPLACE "\\.int\\.c$" "" Exe ${Exe})
#    MESSAGE(${Exe})
#    add_executable(${Exe} ${COMM_SOURCE_FILES} ${test_case})
#ENDFOREACH (test_case)
#
#
#
