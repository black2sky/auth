

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

static char gImei[256] = {0};
static char gImeiDevPath[256] = {0};

void setImeiDevPath(const char* ImeiDevPath)
{
	memset(gImeiDevPath, 0, sizeof(gImeiDevPath));
	strcpy(gImeiDevPath, ImeiDevPath);
}

//int main(int argc, char **argv)
const char* get_imei(int type)
{
	if(strlen(gImei) >= 10)
	{
		return gImei;
	}

	int rc, i;
	int n = 0;
	while(n < 10)
	{
		memset(gImei, 0, sizeof(gImei));
		strcpy(gImei, readImeiString(type));
		if(strlen(gImei) >= 10)
			break;

		n++;
		usleep(500000);
	}

	return gImei;
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

	int fd;
	if(strlen(gImeiDevPath) > 0)
		fd = open(gImeiDevPath, O_RDWR);
	else
		fd = open("/dev/ttyUSB2", O_RDWR);
	if ( fd < 0 )
	{
		LOG("imei, open dev error");
		return imei;
	}

	rc = write(fd, queryStr[type], strlen(queryStr[type]));
	if ( rc < 0 )
	{
		LOG("imei, write query error");
		close(fd);
		return imei;
	}

	memset(bufptr, 0, sizeof(bufptr));
	int count = 0, i;

	int old = fcntl(fd, F_GETFL);
	rc = fcntl(fd, F_SETFL, old | O_NONBLOCK);

	for ( i=0; i<5; i++ )
	{
		rc = read(fd, bufptr+count, sizeof(bufptr)-count);
		if ( rc > 0 )
			count += rc;

		usleep(100*1000);
	}
	
	fcntl(fd, F_SETFL, old);
	close(fd);

	if ( count <= 0 )
	{
		LOG("imei, read dev error");
		return imei;
	}

// parse imei
#ifdef CITOPS	//思拓
	if(strstr(bufptr, "AT+CGSN") != NULL || strstr(bufptr, "AT+GSN") != NULL)
		sscanf(bufptr, "%*[^0-9]%[0-9]", imei);
#ifdef DEBUG
	else
		LOG("parse imei err, bufptr=%s", bufptr);
#endif
#else

	rc = read_sub_string_trim(bufptr, subStr[type], "OK", imei, sizeof(imei));
	if ( rc < 10 )
	{
		if(type == 0)
			LOG("%s, parse cgsn err, bufptr=%s", subStr[type], bufptr);
	}
#endif

#ifdef DEBUG
	LOG("+++: %s", bufptr);
	LOG("IMEI=%s", imei);
#endif
	return imei;
	
}




