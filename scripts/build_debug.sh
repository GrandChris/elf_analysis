
if ! test -f "build/CMakeCache.txt"; then
    source scripts/cmake_configure.sh
fi

cmake --build ./build --config Debug
