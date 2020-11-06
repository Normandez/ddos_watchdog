#!/bin/bash

usage="\
Usage: $0 [OPTION]...

        --builddir=   The build directory
        --prefix=     DDoS Watchdog installation prefix

Optional Features:
    --enable-debug           enable debugging options
    --enable-warnings-all    enable all compiler warnings
    --enable-asan            enable address sanitizer
    --enable-tsan            enable thread sanitizer
"

sourcedir="$( cd "$( dirname "$0" )" && pwd )"

append_cache_entry () {
    CMakeCacheEntries="$CMakeCacheEntries -D $1:$2=$3"
}

# set defaults
builddir=build
prefix=/usr/local/watchdog
CMakeCacheEntries=""
append_cache_entry CMAKE_INSTALL_PREFIX PATH $prefix
append_cache_entry CMAKE_BUILD_TYPE STRING Release

# parse arguments
while [ $# -ne 0 ]; do
    case "$1" in
        *=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
        *) optarg= ;;
    esac

    case "$1" in
        --help|-h)
            echo "${usage}" 1>&2
            exit 1
            ;;
        --builddir=*)
            builddir=$optarg
            ;;
        --prefix=*)
            prefix=$optarg
            append_cache_entry CMAKE_INSTALL_PREFIX PATH $optarg
            ;;
        --enable-debug)
            append_cache_entry CMAKE_BUILD_TYPE STRING Debug
            ;;
        --enable-warnings-all)
            append_cache_entry CMAKE_CXX_FLAGS STRING -Wall
            ;;
        --enable-asan)
            append_cache_entry CMAKE_CXX_FLAGS STRING -fsanitize=address
            ;;
        --enable-tsan)
            append_cache_entry CMAKE_CXX_FLAGS STRING -fsanitize=thread
            ;;
        *)
            echo "Invalid option '$1'.  Try $0 --help to see available options."
            exit 1
            ;;
    esac
    shift
done

if [ -d $builddir ]; then
    if [ -f $builddir/CMakeCache.txt ]; then
        rm -f $builddir/CMakeCache.txt
    fi
else
    mkdir -p $builddir
fi

echo "Build Directory : $builddir"
echo "Source Directory: $sourcedir"
cd $builddir

cmake \
    -DCMAKE_CXX_FLAGS:STRING="$CXXFLAGS $CPPFLAGS" \
    -DCMAKE_C_FLAGS:STRING="$CFLAGS $CPPFLAGS" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    $CMakeCacheEntries $sourcedir

