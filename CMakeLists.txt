cmake_minimum_required(VERSION 3.0.2)
project(ackon-coordinator)

#include_directories(vendor/cargs/include)
#add_subdirectory(vendor/cargs)

set (CMAKE_CXX_FLAGS "-std=c++17 -g -O2")

include_directories(/usr/include/postgresql/)

add_executable(ackon-coordinator main.cpp webserver.cpp sign.cpp format.cpp slots.cpp)

target_link_libraries(ackon-coordinator stdc++fs)
#target_link_libraries(webmake cargs)
target_link_libraries(ackon-coordinator event)
target_link_libraries(ackon-coordinator crypto)
target_link_libraries(ackon-coordinator ssl)
target_link_libraries(ackon-coordinator pq)
