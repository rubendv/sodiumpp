cmake_minimum_required (VERSION 2.6)
project (sodiumpp)

add_definitions(
    -std=c++11 # Or -std=c++0x
)

add_library(sodiumpp SHARED sodiumpp.cpp)
target_link_libraries(sodiumpp sodium)

install_files(/include .h)
install_targets(/lib sodiumpp)
