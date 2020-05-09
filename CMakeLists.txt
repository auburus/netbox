cmake_minimum_required(VERSION 3.17.1)
project(netbox VERSION 0.1.0)

include(CTest)
enable_testing()
add_subdirectory(tests)

add_library(netbox src/netbox.cpp)

target_include_directories(
  netbox
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_options(
  netbox
  PRIVATE -Werror # treat warnings as errors
          -Wall
          -Wextra
          -Wpedantic
          -Wshadow
          -Wnon-virtual-dtor
          -Wold-style-cast
          -Wcast-align
          -Wunused
          -Woverloaded-virtual
          -Wconversion
          -Wsign-conversion
          -Wmisleading-indentation
          -Wduplicated-cond
          -Wduplicated-branches
          -Wlogical-op
          -Wnull-dereference
          -Wuseless-cast
          -Wdouble-promotion
          -Wformat=2
          -Wswitch
          -Wswitch-default
          -Wswitch-enum
          -Wunreachable-code
          -Wuninitialized
          -Wfloat-equal
          -Wreorder
          -Wmissing-braces)

target_compile_features(netbox PUBLIC cxx_std_17)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/GSL)
target_link_libraries(netbox PRIVATE Microsoft.GSL::GSL)
