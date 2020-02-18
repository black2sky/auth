#!/bin/sh
#deinclude CIMI
#arm-hisiv500-linux-g++ -shared -o libtocken.so -fPIC *.cpp
#include CIMI

rm libtocken.so test 
arm-hisiv500-linux-g++ -shared -o libtocken.so -fPIC -DDEBUG  md5.cpp myaes.cpp get_imei.cpp tocken.cpp -I/home/blacksky/src/auth/sdk/hisiv500/include -L/home/blacksky/src/auth/sdk/hisiv500/lib -lcrypto -lssl

arm-hisiv500-linux-g++ test.cpp -L. -ltocken -lpthread -o test 

