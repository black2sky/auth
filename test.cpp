#include <iostream>
#include <unistd.h>
#include <tocken.h>

int main()
{
	authentication("123456789", "test");
	while(1)
		usleep(1000000);
	return 0;
}
