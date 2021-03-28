# elf_analysis   [![Build Actions Status](https://github.com/GrandChris/elf_analysis/workflows/Build/badge.svg)](https://github.com/GrandChris/elf_analysis/actions)
Reads an .elf file and parses the .text and .debug_line sections. It assigns every instruction
a source file and a line number. The data is provided through a C interface. The source code
is compiled to WebAssembly using [Emscripten](https://emscripten.org/) to be used in the VS-Code extension [Elf Lens](https://github.com/GrandChris/elf_analysis).  

## Features

### What it does

- Parses an .elf file using [elfio](https://github.com/serge1/ELFIO)
- Disassembles the '.text' section using [capstone](https://github.com/aquynh/capstone)
- Decodes the '.debug_line' section using a diy implementation
- Provides a C interface to access the data

### Development environment

- Uses VSCode [Remote-Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for development
- Uses the same Docker container to build the project with [Github Actions](https://github.com/GrandChris/elf_analysis/actions)
- Dependencies (elfio and capstone) are fetched during CMake configure with [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html)
- The source code is compiled using GCC 10
- The source code is compiled using [Emscripten](https://emscripten.org/)


## Limitations
- It is designed to work with a small codebase (for embedded development)
- It supports only 'ARM Thumb Code' for the '.text' section and 'Dwarf 3' debug information (standard when building with GCC)  in the '.debug_line' section
- It also has a limited support for 'x86-64' code (no guarantees here)

## How to build
#### GCC
```bash
# assuming CMake, Ninja and GCC 10 is installed
cmake -G Ninja -S . -B ./build
cmake --build ./build
```
### Emscripten
```bash
# assuming CMake, Ninja, LLVM and Emscripten is installed
cmake -G Ninja -S . -B ./build -DCMAKE_TOOLCHAIN_FILE=/emsdk/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake 
cmake --build ./build
```
You can also use the VS-Code extension Remote-Containers and run the predefined Tasks to build this project.  
Note that building this project was only tested with Ubuntu Groovy so far.


