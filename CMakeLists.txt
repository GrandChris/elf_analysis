#
# \file       CMakeLists.txt
# \author     GrandChris
# \date       2020-10-11
# \brief      Build the library
#

cmake_minimum_required(VERSION 3.16)


############################################################################
# Library

# Create the project
project(elf_analysis)

# Export compile commands for VSCode C++ Intellisense
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory("libelfin")

# # Add executable
# add_library(${PROJECT_NAME} INTERFACE)

# # Include directories
# target_include_directories(${PROJECT_NAME} INTERFACE "./include")

# ############################################################################
# # Exe

# if(ENABLE_TESTS)

#   set(PROJECT_EXE_NAME ${PROJECT_NAME}_run)

#   add_executable(${PROJECT_EXE_NAME})

#   set_property(TARGET ${PROJECT_EXE_NAME} PROPERTY CXX_STANDARD 20)

#   target_compile_options(${PROJECT_EXE_NAME} PRIVATE
#     -fcoroutines 

#     -fdiagnostics-color
#     -Wall 

#     -fsanitize=address 
#     -fsanitize=undefined
#     -fsanitize=leak

#     $<$<CONFIG:Debug>:-g -O0>
#     $<$<CONFIG:Release>:-g -O3>
#   )

#   # Add source files
#   file(GLOB SOURCE_FILES_EXE CONFIGURE_DEPENDS
#     "./app/*.cpp"
#   )

#   target_sources(${PROJECT_EXE_NAME} PRIVATE ${SOURCE_FILES_EXE})

#   # Add cppcoro
#   target_link_libraries(${PROJECT_EXE_NAME} PRIVATE 
#     ${PROJECT_NAME}
#     ${LIBASAN}
#     ${LIBLSAN}
#     ${LIBUBSAN}
#   )

# endif()

# ############################################################################
# # Unit Tests

# if(ENABLE_TESTS)

#   set(PROJECT_TEST_NAME ${PROJECT_NAME}_tests)

#   add_executable(${PROJECT_TEST_NAME})

#   set_property(TARGET ${PROJECT_TEST_NAME} PROPERTY CXX_STANDARD 20)

#   target_compile_options(${PROJECT_TEST_NAME} PRIVATE
#     -fcoroutines 

#     -fdiagnostics-color
#     -Wall 

#     -fsanitize=address 
#     -fsanitize=undefined
#     -fsanitize=leak

#     $<$<CONFIG:Debug>:-g -O0>
#     $<$<CONFIG:Release>:-g -O3>
#   )

#   # Add source files
#   file(GLOB SOURCE_FILES_TEST CONFIGURE_DEPENDS
#       "./test/*.cpp"
#   )

#   target_sources(${PROJECT_TEST_NAME} PRIVATE ${SOURCE_FILES_TEST})

#   # Add cppcoro
#   target_link_libraries(${PROJECT_TEST_NAME} PRIVATE 
#     ${PROJECT_NAME}
#     ${LIBASAN}
#     ${LIBLSAN}
#     ${LIBUBSAN}
#   )

#   # Add GTest
#   find_package(GTest CONFIG REQUIRED)

#   target_link_libraries(${PROJECT_TEST_NAME} PRIVATE GTest::gtest_main)

#   enable_testing()
#   include(GoogleTest)
#   gtest_discover_tests(${PROJECT_TEST_NAME})

# endif()






