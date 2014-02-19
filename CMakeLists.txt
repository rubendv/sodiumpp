cmake_minimum_required (VERSION 2.6)
project (sodiumpp)

INCLUDE_DIRECTORIES(/opt/local/include)
LINK_DIRECTORIES(/opt/local/lib)

add_library(sodiumpp SHARED sodiumpp.cpp)
target_link_libraries(sodiumpp sodium)

install_files(/include .h)
install_targets(/lib sodiumpp)
