all: c-format.so

CXX=g++-8

PLUGBASE=`$(CXX) -print-file-name=plugin`
CPPFLAGS=-I$(PLUGBASE)/include -I$(PLUGBASE)/include/c-family

c-format.so: c-format.o
	$(CXX) -g -shared -o $@ $^

c-format.o: c-format.c gcc-common.h
	$(CXX) -g $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<
