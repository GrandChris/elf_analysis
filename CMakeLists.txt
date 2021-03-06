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

  # Sanitizers https://github.com/google/sanitizers
  set(LIBASAN  asan)  # Address sanitizer
  set(LIBLSAN  lsan)  # Leak sanitizer
  set(LIBUBSAN ubsan) # Undefined behavior sanitizer

add_compile_options(
    -fdiagnostics-color
    -Wall
    
    # -ffunction-sections
    # -fdata-sections
    -O3
    # -gdwarf-3
    # -ggdb3
)



if (EMSCRIPTEN)

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
     -s DISABLE_EXCEPTION_CATCHING=0 \
     -s FORCE_FILESYSTEM=1 \
     -s EXPORTED_RUNTIME_METHODS='[ccall, cwrap]' \
     -s MODULARIZE \
     -s TOTAL_MEMORY=1024MB "
     )
     #  -s ALLOW_MEMORY_GROWTH=1 \
     #  -s EXPORTED_FUNCTIONS=['_sayHi'] \
else()
    add_compile_options(
        -fsanitize=address 
        -fsanitize=undefined
        -fsanitize=leak
    )
endif()

# Add library
add_library(elf_analysis_lib)

target_compile_options(elf_analysis_lib PUBLIC 
    -ggdb3
)
    
    # Set compile options
    # set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
    
    # target_compile_options(${PROJECT_NAME} PRIVATE
    
    # )
    
# Include Directories
target_include_directories(elf_analysis_lib PUBLIC 
    "./include"
    # "./capstone/include"
    "${CMAKE_BINARY_DIR}/_deps/capstone-src/include"

)
    
    # Add source files
file(GLOB SOURCE_FILES CONFIGURE_DEPENDS
    "./source/*.cpp"
    "./source/*/*.cpp"
    "./source/*/*/*.cpp"
)

target_sources(elf_analysis_lib PUBLIC ${SOURCE_FILES})

# Link libraries
target_link_libraries(elf_analysis_lib PUBLIC 
    elfio
    capstone-static
    $<$<CXX_COMPILER_ID:Clang>:nodefs.js>
)

# target_link_options(elf_analysis_lib PUBLIC
#     # LINKER:-Map=mapfile
#     LINKER:-gc-sections
# )

if (EMSCRIPTEN)
    target_link_options(elf_analysis_lib PUBLIC
        LINKER: -s DISABLE_EXCEPTION_CATCHING=0
        # LINKER: -s ALLOW_MEMORY_GROWTH=1
    )
else()
    target_link_libraries(elf_analysis_lib PUBLIC 
        ${LIBASAN}
        ${LIBLSAN}
        ${LIBUBSAN}
    )
endif()

# compile librarys
include(FetchContent)

# elfio
FetchContent_Declare(
    ELFIO
    GIT_REPOSITORY https://github.com/serge1/ELFIO.git
    GIT_TAG        Release_3.8
)
FetchContent_MakeAvailable(ELFIO)
        
FetchContent_Declare(
    CAPSTONE
    GIT_REPOSITORY https://github.com/aquynh/capstone.git
    GIT_TAG        4.0.2
)

#capstone
option(CAPSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" OFF)
option(CAPSTONE_BUILD_STATIC "Build static library" ON)
option(CAPSTONE_BUILD_SHARED "Build shared library" OFF)
option(CAPSTONE_BUILD_DIET "Build diet library" OFF)
option(CAPSTONE_BUILD_TESTS "Build tests" OFF)
option(CAPSTONE_BUILD_CSTOOL "Build cstool" OFF)
option(CAPSTONE_USE_DEFAULT_ALLOC "Use default memory allocation functions" ON)
option(CAPSTONE_ARCHITECTURE_DEFAULT "Whether architectures are enabled by default" ON)

FetchContent_MakeAvailable(CAPSTONE)

# compile app
add_subdirectory("app")

# compile tests
if(ENABLE_TESTS)
    add_subdirectory("test")
endif()