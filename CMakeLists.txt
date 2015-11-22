cmake_minimum_required(VERSION 3.1)
project(DCHash)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Werror -pedantic -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls")

set(SOURCE_FILES lib/hash_function.c lib/md5.c lib/sha1.c DCuckooHash.c)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(DCHash ${SOURCE_FILES} main.c)
