cmake_minimum_required(VERSION 3.5.1)
project(TPM2_0_TSS_DUPLICATE)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
add_definitions(-DMAXLOGLEVEL=6)
add_definitions(-DOSSL)


set(SOURCE_FILES
    integration/duplicate.c
    integration/main-esapi.c
    integration/sapi-test-options.c
    integration/sapi-context-util.c

    tss2-esys/esys_context.c
    tss2-esys/esys_crypto.c
    tss2-esys/esys_crypto_gcrypt.c
    tss2-esys/esys_crypto_ossl.c
    tss2-esys/esys_free.c
    tss2-esys/esys_iutil.c
    tss2-esys/esys_mu.c
    tss2-esys/esys_tcti_default.c
    tss2-esys/esys_tr.c

    tss2-sys/sysapi_util.c

    tss2-tcti/tcti-common.c
    #tss2-tcti/tcti-device.c
    tss2-tcti/tcti-mssim.c

    util/log.c
)

INCLUDE_DIRECTORIES(
    ./
    ./integration
    ./tss2-esys
    ./tss2-sys
    ./tss2-tcti
    ./util
    /usr/local/include/tss2
)

LINK_DIRECTORIES(
    .
    /usr/local/lib
)

LINK_LIBRARIES(
    libcrypto.so
    libssl.so
    libdl.so
    libgcrypt.so
    libtss2-mu.so
    libtss2-esys.so
    libtss2-sys.so
    libtss2-tcti-device.so
    libtss2-tcti-mssim.so
)

add_executable(duplicate ${SOURCE_FILES})
target_link_libraries(duplicate)

