1. 生成so库libtocken.so
(1)生成鉴权码不含CIMI
arm-hisiv500-linux-g++ tocken.cpp md5.cpp  get_imei.cpp -fPIC -shared -o libtocken.so (或者arm-hisiv500-linux-g++ -shared -o libtocken.so -fPIC *.cpp)
(2)生成鉴权码包含CIMI
arm-hisiv500-linux-g++ tocken.cpp md5.cpp  get_imei.cpp -D=CIMI -fPIC -shared -o libtocken.so (或者arm-hisiv500-linux-g++ -shared -o libtocken.so -D=CIMI -fPIC *.cpp)

arm-hisiv500-linux-strip libtocken.so
arm-hisiv500-linux-g++ test.cpp -o test -L./ -ltocken -lpthread
export LD_LIBRARY_PATH=/home/blacksky/src/token:$LD_LIBRARY_PATH

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.

2. 生成jni库libdsai-md5.so
g++ -I/home/blacksky/src/token/jdk1.7.0_80/include -I/home/blacksky/src/token/jdk1.7.0_80/include/linux -fPIC -shared -o libdsai-md5.so javaMd5.cpp md5.cpp

g++ -I/home/blacksky/src/lib/jdk1.7.0_80/include -I/home/blacksky/src/lib/jdk1.7.0_80/include/linux -I/home/blacksky/src/lib/include -fPIC -shared -o libdsai-sha512.so javaSHA512.cpp -L/home/blacksky/src/lib/lib -lssl -lcrypto
./config no-asm --prefix=/home/liguangyang/dengwenjun/lib -fPIC
./config -t

arm-hisiv500-linux-g++ test.cpp -I ./include -L/home/liguangyang/dengwenjun/lib/lib -lssl -lcrypto -o test


/home/liguangyang/dengwenjun/lib/lib
/home/liguangyang/dengwenjun/lib/include/

-fPIC -shared -I ./include -L/home/blacksky/src/lib/lib/ -lcrypto -lssl

arm-hisiv500-linux-g++ -shared -o libtocken.so -fPIC *.cpp -I/home/liguangyang/dengwenjun/lib/include/ -L/home/liguangyang/dengwenjun/lib/lib -lcrypto -lssl
arm-hisiv500-linux-strip libtocken.so