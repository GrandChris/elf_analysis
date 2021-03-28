#
# \file       CMakeLists.txt
# \author     GrandChris
# \date       2020-10-11
# \brief      Build the unit tests
#

cmake_minimum_required(VERSION 3.16)

# Add exe
add_executable(elf_analysis)
    
# Add source files
 file(GLOB APP_SOURCE_FILES CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
    )
    
target_sources(elf_analysis PRIVATE ${APP_SOURCE_FILES})
    
 # Link libraries
target_link_libraries(elf_analysis PRIVATE 
    elf_analysis_lib
)


