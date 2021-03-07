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

add_compile_options(
    -O0
)

if (EMSCRIPTEN)
    add_compile_options(
        -s DISABLE_EXCEPTION_CATCHING=0
    )
endif()

# Add exe
add_executable(${PROJECT_NAME})

# Set compile options
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_compile_options(${PROJECT_NAME} PRIVATE
    -fdiagnostics-color
    -Wall 
    -ggdb3
)

# Include Directories
target_include_directories(${PROJECT_NAME} PRIVATE 
    "./include"
)
    
# Add source files
 file(GLOB SOURCE_FILES CONFIGURE_DEPENDS
    "./app/*.cpp"
    )
    
target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})
    
 # Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE 
    elf
    dwarf
    $<$<CXX_COMPILER_ID:Clang>:nodefs.js>
)

target_link_options(${PROJECT_NAME} PRIVATE
    # LINKER:-Map=mapfile
)

if (EMSCRIPTEN)
    target_link_options(${PROJECT_NAME} PRIVATE
        LINKER: -s DISABLE_EXCEPTION_CATCHING=0>
    )
endif()

# compile librarys
add_subdirectory("libelfin")


