#
# \file       CMakeLists.txt
# \author     GrandChris
# \date       2020-10-11
# \brief      Build the unit tests
#

cmake_minimum_required(VERSION 3.16)

# Add exe
add_executable(unit_tests)
    
# Add source files
file(GLOB SOURCE_FILES_UNIT_TESTS CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

target_sources(unit_tests PRIVATE ${SOURCE_FILES_UNIT_TESTS})

    
 # Link libraries
target_link_libraries(unit_tests PRIVATE 
    elf_analysis
    gtest
    gtest_main
)

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG         release-1.10.0
)

FetchContent_MakeAvailable(googletest)
