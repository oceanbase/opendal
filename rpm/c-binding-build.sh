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
wget http://mirrors.aliyun.com/oceanbase/OceanBase.repo -P /etc/yum.repos.d/
yum install obdevtools-cmake-3.22.1 -y
yum install obdevtools-gcc9-9.3.0 -y

export PATH=/usr/local/oceanbase/devtools/bin:$PATH

# build rpm
cd $BASE_DIR
export PROJECT_NAME=${PROJECT_NAME}
export RELEASE=${RELEASE}
# 打包
# release rpm
rpmbuild -vv --define "_topdir $RPM_BUILD_DIR" -bb $CUR_DIR/c-binding.spec
# 将rpm文件拷贝到rpm目录
find $RPM_BUILD_DIR/ -name "*.rpm" -exec mv {} $CUR_DIR 2>/dev/null \;
# 删除.rpm_build目录
rm -rf $RPM_BUILD_DIR
