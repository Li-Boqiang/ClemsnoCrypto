./autogen.sh --with-jemalloc-prefix=mpk_ --prefix=$(realpath ..)
make
make install