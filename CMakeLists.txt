cmake_minimum_required(VERSION 3.8)

project(fpe_wdc)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

set(LIB_SRC ff1.c ff3.c fpe_locl.c)
add_library(fpe_static ${LIB_SRC})
add_library(fpe SHARED ${LIB_SRC})
target_link_libraries(fpe ${OPENSSL_LIBRARIES} m)

add_executable(UTest test.c)
target_link_libraries(UTest fpe)
