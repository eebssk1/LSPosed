cmake_minimum_required(VERSION 3.4.1)

add_library(yahfa STATIC src/HookMain.cpp src/trampoline.c)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1")

find_library(log-lib log)
target_link_libraries(yahfa ${log-lib})
target_include_directories(yahfa PUBLIC include)
