#!/bin/bash

REDHAT=$(grep -Po '(?<=release )\d' /etc/redhat-release)
ID=$(grep -Po '(?<=^ID=).*' /etc/os-release | tr -d '"')
DOWNLOAD_BASE_URL="https://mirrors.aliyun.com/oceanbase/development-kit/el/"
CUR_DIR=$(dirname $(readlink -f "$0"))

# 安装依赖
ARCH=`uname -p`
TARGET_DIR_3rd=${CUR_DIR}/deps/3rd
PKG_DIR=${TARGET_DIR_3rd}/pkg
mkdir -p $PKG_DIR
if [[ "${ID}"x != "alinux"x ]]; then
    dep_pkgs=(
        obdevtools-cmake-3.22.1-22022100417.el
        obdevtools-gcc9-9.3.0-52022092914.el
        devdeps-gtest-1.8.0-132022101316.el
    )

    for dep in ${dep_pkgs[@]}
    do
        TEMP=$(mktemp -p "/" -u ".XXXX")
        deps_url=${DOWNLOAD_BASE_URL}/${REDHAT}/${ARCH}
        pkg=${dep}${REDHAT}.${ARCH}.rpm
        wget $deps_url/$pkg -O $PKG_DIR/$TEMP
        if [[ $? == 0 ]]; then
            mv -f $PKG_DIR/$TEMP $PKG_DIR/$pkg 
        fi 
        (cd $TARGET_DIR_3rd && rpm2cpio $PKG_DIR/$pkg | cpio -di -u --quiet)
    done

    export PATH=$TARGET_DIR_3rd/usr/local/oceanbase/devtools/bin:$PATH
    export CC=$TARGET_DIR_3rd/usr/local/oceanbase/devtools/bin/gcc
    export CXX=$TARGET_DIR_3rd/usr/local/oceanbase/devtools/bin/g++
fi

cd ${CUR_DIR}
rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DUSE_GTEST=ON
cp compile_commands.json ..