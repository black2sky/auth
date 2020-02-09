#!/bin/sh
#deinclude CIMI
#arm-hisiv500-linux-g++ -shared -o libtocken.so -fPIC *.cpp
#include CIMI
#arm-hisiv500-linux-g++ -shared -o libtocken.so -D=CIMI -fPIC *.cpp

#arm-hisiv500-linux-strip libtocken.so
rm test libtocken.so
export LD_LIBRARY_PATH=/home/black2sky/src/auth/sdk:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
g++ -shared -o libtocken.so -fPIC *.cpp -I /home/black2sky/src/auth/sdk/include/ -L /home/black2sky/src/auth/sdk/ -lcrypto -lssl

g++ test.cpp -o test -I/home/black2sky/src/auth/sdk/ -L/home/black2sky/src/auth/sdk/ -ltocken -lpthread
