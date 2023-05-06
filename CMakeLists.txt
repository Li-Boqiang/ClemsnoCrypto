cmake_minimum_required(VERSION 3.1)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

message(${LLVM_LIBRARY_DIRS})

file(GLOB SAA_SRCS "src/*.cpp")
include_directories("include/")

add_library(SAAPass MODULE ${SAA_SRCS})
target_compile_features(SAAPass PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(SAAPass PROPERTIES
    COMPILE_FLAGS "-O2 -g -fno-rtti -Wall"
)

# add_subdirectory(tools) # For utilities
