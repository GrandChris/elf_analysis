cmake -B ./build_emcc -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=/emsdk/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=TRUE
