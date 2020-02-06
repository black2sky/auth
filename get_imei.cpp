

/*

编译方法

arm-hisiv500-linux-g++ test_lib_dvr_auth.cpp -ldl -rdynamic

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "get_imei.h"

// type=0:imei, type=1:cimi
const char *readImeiString(int type);
bool writeEncryptedString(const char* str);
const char *readEncryptedString();


//int main(int argc, char **argv)
const char* get_imei(int type)
{
	int rc, i;

	const char *imei = readImeiString(type);
	//printf("read imei=%s\n", imei);

	return imei;
}



int ze_read_sub_string_imei(const char *str, const char *begin, const char *end, char *dst, int sizeof_dst)
{
	if ( str == NULL || begin == NULL || end == NULL || dst == NULL || sizeof_dst <= 0 )
	{
		return -1;
	}
	
	int i, len=0;
	char *p1, *p2;
	
	p1 = strstr((char *)str, begin);
	if ( p1 != NULL )
	{
		p2 = strstr(p1 + strlen(begin), end);
		if ( p2 == NULL )
		{
			len += snprintf(dst, sizeof_dst, "%s", p1+strlen(begin));
		}
		else
		{
			len += snprintf(dst, sizeof_dst, "%.*s", p2-(p1+strlen(begin)), p1+strlen(begin));
		}
	}
	
	dst[len] = 0; // 字符串结束符
	return len;
}


#define is_space(a)	((a)==' ' || (a)=='\t' || (a)=='\r' || (a)=='\n')
static int ze_trim_string_find(char **theString, int length)
{
	int i;
	int flag1=0,flag2=0;
	for ( i=0; i<length; ++i )
	{		
		if( !flag2 && !is_space((*theString)[length-i-1]) ) // 去掉后面的空白
		{
			length -= i;
			flag2=1;
			if(flag1 && flag2)
				break;
		}
		
		if( !flag1 && !is_space((*theString)[i]) ) // 去掉前面的空白
		{
			*theString = *theString + i;
			length -= i;
			flag1=1;
			if(flag1 && flag2)
				break;
		}
	}
	if ( flag1 && flag2 )
		return length;
	else
		return 0;
}
// 去掉字符串前后空格
int ze_trim_string_imei(char *str)
{
	char *p = str;
	int rc = ze_trim_string_find(&p, strlen(p));
	if ( rc > 0 )
		memmove(str, p, rc);
	str[rc] = '\0';
	return rc;
}

// 读出子字符串
int read_sub_string_trim(const char *str, const char *begin, const char *end, char *dst, int sizeof_dst)
{
	int rc = ze_read_sub_string_imei(str, begin, end, dst, sizeof_dst);
	ze_trim_string_imei(dst);
	
	// 去掉冒号
	char *p = strstr(dst, ": ");
	if ( p != NULL )
	{
		char tmpstr[4096];
		strcpy(tmpstr, p+2);
		strcpy(dst, tmpstr);
	}
	return strlen(dst);
}


const char *readImeiString(int type)
{
	int rc;
	char bufptr[16*1024];
	static char imei[256];
	static const char *queryStr[2] = { "AT+CGSN\r\n", "AT+CIMI\r\n" };
	static const char *subStr[2] = { "+CGSN", "CIMI" };

	int fd = open("/dev/ttyUSB2", O_RDWR);
	if ( fd < 0 )
	{
		printf("imei, open dev error\n");
		return NULL;
	}

	rc = write(fd, queryStr[type], strlen(queryStr[type]));
	if ( rc < 0 )
	{
		printf("imei, write query error\n");
		close(fd);
		return NULL;
	}

	memset(bufptr, 0, sizeof(bufptr));
	int count = 0, i;

	rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	for ( i=0; i<5; i++ )
	{
		rc = read(fd, bufptr+count, sizeof(bufptr)-count);
		if ( rc > 0 )
			count += rc;

		usleep(100*1000);
	}
	
	close(fd);
	if ( count <= 0 )
	{
		printf("imei, read dev error\n");
		return NULL;
	}

	// parse imei
	rc = read_sub_string_trim(bufptr, subStr[type], "OK", imei, sizeof(imei));
	if ( rc < 10 )
	{
		if(type == 0)
		{
			printf("%s, parse cgsn err, bufptr=%s\n", subStr[type], bufptr);
		}
		return NULL;
	}

	//printf("read imei=%s\n", imei);
	return imei;
	
}



