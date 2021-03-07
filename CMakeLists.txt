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
set(CMAKE_CXX_STANDARD 20)

add_compile_options(
    -fdiagnostics-color
    -Wall
    
    # -ffunction-sections
    # -fdata-sections
    
    -O0
    -ggdb3
)

if (EMSCRIPTEN)
    add_compile_options(
        # -s DISABLE_EXCEPTION_CATCHING=0
        -s ALLOW_MEMORY_GROWTH=1
    )
endif()

# Add library
add_library(${PROJECT_NAME})

# Set compile options
# set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

# target_compile_options(${PROJECT_NAME} PRIVATE

# )

# Include Directories
target_include_directories(${PROJECT_NAME} PUBLIC 
    "./include"
)
    
# Add source files
 file(GLOB SOURCE_FILES CONFIGURE_DEPENDS
    "./source/*.cpp"
    )
    
target_sources(${PROJECT_NAME} PUBLIC ${SOURCE_FILES})
    
 # Link libraries
target_link_libraries(${PROJECT_NAME} PUBLIC 
    elf
    dwarf
    $<$<CXX_COMPILER_ID:Clang>:nodefs.js>
)

# target_link_options(${PROJECT_NAME} PUBLIC
#     # LINKER:-Map=mapfile
#     LINKER:-gc-sections
# )

if (EMSCRIPTEN)
    target_link_options(${PROJECT_NAME} PUBLIC
        # LINKER: -s DISABLE_EXCEPTION_CATCHING=0
        LINKER: -s ALLOW_MEMORY_GROWTH=1
    )
endif()

# compile librarys
add_subdirectory("libelfin")

# # compile app
add_subdirectory("app")

# # compile tests
if(ENABLE_TESTS)
    add_subdirectory("test")
endif()