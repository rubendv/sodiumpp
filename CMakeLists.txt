cmake_minimum_required (VERSION 2.6)
project (sodiumpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

if(DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O0 -g")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O2 -DNDEBUG")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -DNDEBUG")
endif()

if(SODIUMPP_MACPORTS)
    include_directories("/opt/local/include")
    link_directories("/opt/local/lib")
endif()

include_directories($(CMAKE_CURRENT_SOURCE_DIR)/sodiumpp/include)

if(SODIUMPP_STATIC)
	add_library(sodiumpp STATIC sodiumpp/sodiumpp.cpp sodiumpp/z85/z85.c sodiumpp/z85/z85_impl.cpp)
else()
	add_library(sodiumpp SHARED sodiumpp/sodiumpp.cpp sodiumpp/z85/z85.c sodiumpp/z85/z85_impl.cpp)
	target_link_libraries(sodiumpp sodium)
endif()

if(SODIUMPP_EXAMPLE)
	add_executable(example sodiumpp/example.cpp)
	target_link_libraries(example sodiumpp)
endif()

if(SODIUMPP_TEST)
    add_executable(tests sodiumpp/test.cpp)
    target_link_libraries(tests sodiumpp)
endif()

install(DIRECTORY sodiumpp/include/sodiumpp DESTINATION include)
install_targets(/lib sodiumpp)
