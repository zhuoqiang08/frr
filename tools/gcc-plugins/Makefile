all: my-format.so

CXX=g++-8

PLUGBASE=`$(CXX) -print-file-name=plugin`
CPPFLAGS=-I$(PLUGBASE)/include -I$(PLUGBASE)/include/c-family

my-format.so: my-format.o
	$(CXX) -g -shared -o $@ $^

my-format.o: my-format.c gcc-common.h
	$(CXX) -g $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<
