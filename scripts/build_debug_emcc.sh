
if ! test -f "build_emcc/CMakeCache.txt"; then
    source scripts/cmake_configure_emcc.sh
fi

cmake --build ./build_emcc --config Debug
