cmake_minimum_required(VERSION 3.9)

project(PROTOPARSER)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)
set(SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)

include(FetchContent)

# add thread suport in unix.
if(UNIX)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

# link llhttp to project.
find_library(llhttp_location NAMES libllhttp.a)
if(llhttp_location)
    message(STATUS "llhttp location is: ${llhttp_location}")
    add_library(llhttp STATIC IMPORTED)
    set_target_properties(llhttp PROPERTIES IMPORTED_LOCATION ${llhttp_location})
else()
    FetchContent_Declare(llhttp URL "https://github.com/nodejs/llhttp/archive/refs/tags/v6.0.5.tar.gz")  # Using version 6.0.5
    FetchContent_MakeAvailable(llhttp)
    # target_link_libraries(${EXAMPLE_PROJECT_NAME} ${PROJECT_LIBRARIES} llhttp ${PROJECT_NAME})
endif()
# target_link_libraries(llhttp INTERFACE Threads::Threads)

# link libpcap to project/
find_library(libpcap_location NAMES libpcap.so)
if(libpcap_location)
    message(STATUS "libpcap location is: ${libpcap_location}")
    add_library(libpcap SHARED IMPORTED)
    set_target_properties(libpcap PROPERTIES IMPORTED_LOCATION ${libpcap_location})
endif()

set(PARSER_SRC
    src/lpcap.cc
    src/http.cc
    src/parser.cc
    src/native/api.c
    src/native/http.c
    src/native/llhttp.c)

add_library(PParser STATIC ${PARSER_SRC})
target_compile_features(PParser PRIVATE cxx_std_17)
target_link_libraries(PParser PRIVATE llhttp)
target_link_libraries(PParser PRIVATE libpcap)

# Build main target.
add_executable(main main.cc)
target_link_libraries(main PRIVATE libpcap)
target_include_directories(main PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(main PUBLIC PParser)
target_compile_features(main PUBLIC cxx_std_11)

# # Build map_test target.
# add_executable(map_test map_test.cc)
# target_link_libraries(map_test PRIVATE libpcap)
# target_include_directories(map_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
# target_link_libraries(map_test PUBLIC PParser)
# target_compile_features(map_test PUBLIC cxx_std_17)