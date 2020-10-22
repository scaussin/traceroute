cmake_minimum_required(VERSION 3.17)
project(traceroute)

set(CMAKE_CXX_STANDARD 14)

include_directories(inc)

add_executable(traceroute
        inc/main.h
        src/main.cpp)
