#!/bin/bash

# Usage: c-binding-build.sh <path> <package> <version> <release>
# 前三个参数是为了保持和observer build脚本使用方式一致,并没有用到

if [ $# -ne 4 ]
then
    echo "Usage: c-binding-build.sh <path> <package> <version> <release>"
    exit 1
else
    REDHAT=$(grep -Po '(?<=release )\d' /etc/redhat-release)
    ID=$(grep -Po '(?<=^ID=).*' /etc/os-release | tr -d '"')
    if [[ "${ID}"x == "alinux"x ]]; then
        RELEASE="$4.al8"
    else
        RELEASE="$4.el${REDHAT}"
        DOWNLOAD_BASE_URL="https://mirrors.aliyun.com/oceanbase/development-kit/el/"
    fi
fi

PROJECT_NAME=obdal

CUR_DIR=$(dirname $(readlink -f "$0"))
BASE_DIR=$CUR_DIR/..  # pwd的父目录
RPM_BUILD_DIR=$BASE_DIR/.rpm_build
echo "[BUILD] args: CURDIR=${CUR_DIR} PROJECT_NAME=${PROJECT_NAME} RELEASE=${RELEASE}"

# prepare rpm build dirs
rm -rf $RPM_BUILD_DIR
mkdir -p $RPM_BUILD_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# 安装依赖
if [[ "${ID}"x != "alinux"x ]]; then
    dep_pkgs=(
        obdevtools-cmake-3.22.1-22022100417.el
        obdevtools-gcc9-9.3.0-52022092914.el
    )

    ARCH=`uname -p`
    TARGET_DIR_3rd=${CUR_DIR}/deps/3rd
    PKG_DIR=${TARGET_DIR_3rd}/pkg
    mkdir -p $PKG_DIR

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


# build rpm
cd $BASE_DIR
export PROJECT_NAME=${PROJECT_NAME}
export RELEASE=${RELEASE}
# 打包
# release rpm
rpmbuild -vv --define "_topdir $RPM_BUILD_DIR" -bb $CUR_DIR/$PROJECT_NAME.spec
# 将rpm文件拷贝到rpm目录
find $RPM_BUILD_DIR/ -name "*.rpm" -exec mv {} $CUR_DIR 2>/dev/null \;
# 删除.rpm_build目录
rm -rf $RPM_BUILD_DIR
