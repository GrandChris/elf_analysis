# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.145.0/containers/ubuntu/.devcontainer/base.Dockerfile

# [Choice] Ubuntu version: bionic, focal
ARG VARIANT="focal"
FROM ubuntu:groovy

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends --reinstall ca-certificates \
    && apt-get -y install --no-install-recommends git build-essential gdb cmake ninja-build curl unzip tar python3 \
    && apt-get -y install --no-install-recommends libubsan1 libasan6 liblsan0 

# install emscripten
RUN apt-get -y install --no-install-recommends llvm binaryen

RUN git clone https://github.com/emscripten-core/emsdk.git \
    && cd emsdk \
    && git pull \
    && git checkout 2.0.14 \
    && ./emsdk install 2.0.14 \
    && ./emsdk activate 2.0.14 

ENV PATH /emsdk:/emsdk/node/14.15.5_64bit/bin:/emsdk/upstream/emscripten:$PATH

# install arm-none-eabi-gcc
RUN  apt-get -y install --no-install-recommends gcc-arm-none-eabi binutils-arm-none-eabi
# RUN  apt-get -y install --no-install-recommends gdb-arm-none-eabi openocd
