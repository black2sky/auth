#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <setjmp.h>
#include <signal.h>
#include <cstdlib>
#include <ctime>
#include <sys/time.h>

#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/crypto.h"
#include "myaes.h"
#include "md5.h"

#define LOG(format,...) printf("["__DATE__" "__TIME__"] " format "\n",  ##__VA_ARGS__)

#define RET_SUCCESS					0	// 鉴权成功
#define RET_FAIL					-1  // 鉴权失败,license不一致
#define	RET_FAIL_IMEI				2	// IMEI读取失败或者为空
#define	RET_FAIL_COMPANY			3	// 企业不存在
#define	RET_FAIL_VERSION			4	// key不支持该版本
#define RET_FAIL_VERSION_OUT		5	// 授权数超出上限
#define	RET_FAIL_KEY_NULL			6	// 授权key为空
#define RET_FAILE_KEY_NOT_IN_SYS	7	// 授权key在系统中不存在
#define	RET_FAILE_KEY_DISABLE		8	// key已被禁用
#define	RET_FAILE_VERSION_FORMAT_ERR 9	// 算法版本格式不正确

#define RET_FAILE_NET				10	// 网络错误
#define RET_FAILE_OPEN_ERROR		11	// license文件打开失败

#define RET_FAILE_CHECKCODE_OVERTIME	100 // 离线超过时间7天，鉴权无效
#define RET_FAILE_CHECKCODE_BIT_FAUILE	101 // 校验位错误。
#define RET_FAILE_CHECKCODE_WITHOUT		102 // 校验码不存在。
#define RET_FAILE_CHECKCODE_FAUILE		103 // 校验码错误。

#define OUT
#define MAXLINE		4096
#define OVERTIME	60*60*24*7

#define _tocken_register			0x0100 //鉴权注册
#define _tocken_register_new		0x10100//鉴权注册-新
#define _tocken_register_resp		0x8100 //鉴权注册应答

#define _tocken_heartbeat			0x0002 		//终端心跳
#define _tocken_srv_check			0x010102 	//终端鉴权校验
#define _tocken_srv_resp			0x8001 		//通用应答


struct  authenticateInfo
{
	std::string 	ip;				// ip地址
	std::string 	path;			// 鉴权文件地址
	std::string 	pathCheckCode;	// 校验文件地址
	//std::string     company;        // 公司
	//std::string 	deviceType;		// 设备类型
	std::string     key;        	// 公司
	std::string		algVersion;		// 算法版本
};

#define PORT			9191

#ifdef CITOPS	//思拓授权的路径
	#define FILEPATH1		"/mnt/user/dsai"
	//#define FILEPATH1		"/var/disk2/dsai"
#else
	#define FILEPATH1		"/mnt/nand/"
	#define FILEPATH2		"/mnt/sd1/"
	#define FILEPATH3		"/mnt/sd2/"
#endif
	#define FILENAME		"desheng.com"
	#define FILENAME2		"desheng2.com"
	#define SPECIAL_FILE	"/mnt/sd1/special_for_dsai_test.com"

const char* DSIP[3] = {"auth.desheng-ai.com", "www.desheng-ai.com.cn", "183.3.136.80"};

int socket_resolver(const char *domain, char* ipaddr, int len);

class Thread
{
private:
    //当前线程的线程ID
    pthread_t tidSend;
    pthread_t tidRecv;
    static void * thread_proxy_func_send(void * args);
    static void * thread_proxy_func_recv(void * args);

public:
	Thread();
	virtual ~Thread();

	virtual void runSend() = 0;
	virtual void runRecv() = 0;
	void 	start();
};

class tocken : public Thread
{
protected:
	int 	m_nSockFd;
	long 	m_sn;
	int		m_disconnectSec;
	struct  authenticateInfo 	m_info;
 	struct 	sockaddr_in 		m_serverAddr;
	std::string m_IMEI;
	std::string m_CIMI;
	std::string m_UUID;
	std::string m_MAC;

 	struct 	head;
	struct 	tocken_register; 					//鉴权注册
	struct 	tocken_register_new; 				//鉴权注册-新
	struct 	tocken_register_resp; 				//鉴权注册应答
	struct 	tocken_heartbeat; 					//终端心跳
	struct	tocken_srv_check;					//服务器连接验证
	struct	tocken_srv_check_resp;				//服务器连接验证应答

private:
	static tocken* m_pTocken;
public:
	static tocken* GetInstance(authenticateInfo &info)
	{
	     if(m_pTocken == NULL)
	     {
	    	 m_pTocken = new tocken();
	    	 m_pTocken->init(info);
	     }

	     return m_pTocken;
	}
	tocken();
 	virtual ~tocken();

	int 	authenticate(std::string key, std::string algVersion);
	int		getToken();
	void 	init(struct authenticateInfo &info);
	void	setCheckCode(int type);
	int		checkCheckCode();
	static	int	checkPath(const char * p);

	static bool	isRunning;
	static long long checkCode;

private:
 	int		CreateTcpSocket();
	bool	Connect();
	bool	ReConnect(int n);
	int		Send(const char* pBuf, int nLen);
	int 	Recv(char* pBuf, int nLen);
	void 	Close();
	void 	runSend();
	void 	runRecv();
	void 	saveTocken(char* buf);

	int 	netdev_get_mac(const char *devname, OUT char *macstr, int macstr_len);
	long 	getSN();
	void 	getCompany(OUT std::string &company);
};

#include "get_imei.h"
#include "tocken.h"


/*
ERROR #00001  ====> imei, open dev error
*/

static sigjmp_buf				jmpbuf;
static volatile sig_atomic_t	canjump;
static void tcl_sig_alrm(int signo)
{
    if (!canjump)
    {
        return;

    }
    siglongjmp(jmpbuf, 1);
}

int socket_resolver(const char *domain, char* ipaddr, int len)
{
        struct addrinfo hints;
        struct addrinfo *result, *result_pointer;
        int ret;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;			//	指定使用IPv4
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;
        hints.ai_protocol = 0;  

        if (signal(SIGALRM, tcl_sig_alrm) == SIG_ERR)
        {
            return -1;
        }

        if (sigsetjmp(jmpbuf, 1))
        {
            printf("DNS time out\n");		//	域名解析超时，退出阻塞
            alarm(0);
            return -1;
        }

        canjump = 1;
        alarm(15);							//	设置定时器，DNS解析超过15秒，就退出
        ret = getaddrinfo(domain, NULL, &hints, &result);
        canjump = 0;

        if (ret != 0)
        {
                return -1;
        }

        for (result_pointer = result; result_pointer != NULL; result_pointer = result_pointer->ai_next)
        {
                ret = getnameinfo(result_pointer->ai_addr, result_pointer->ai_addrlen, ipaddr, len, NULL, 0, NI_NUMERICHOST);
                if (ret != 0)
                {
                        continue;
                }
                else
                {					
						break;
                }
        }
        freeaddrinfo(result);

		return 0;
}

tocken* tocken::m_pTocken = NULL;
bool	tocken::isRunning = false;
long long tocken::checkCode = -1;
static pthread_mutex_t m_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m_lockSec = PTHREAD_MUTEX_INITIALIZER;

int authentication(std::string key, std::string algVersion, std::string imeiDevPath)
{
	int pos = key.find("_");	// id_key, 分割id和key
	key = key.substr(pos + 1);
	std::string KEY = key;
	if(imeiDevPath.length() != 0)
		setImeiDevPath(imeiDevPath.c_str());
#ifdef DEBUG
	std::cout << "Key: " << key << std::endl;
	//检查是否存在测试KEY，存在则使用测试KEY测试
	pthread_mutex_lock(&m_lock);
    FILE *fp = NULL;
    char buff[255];
    fp = fopen(SPECIAL_FILE, "r");

    if(fp != NULL)
    {
    	fgets(buff, 255, (FILE*)fp);
    	if(strlen(buff) > 0)
    	{
    		KEY = buff;
    		std::cout << "special for dsai test: " <<  KEY << std::endl;
    	}
    	fclose(fp);
    }
    pthread_mutex_unlock(&m_lock);
#endif

	authenticateInfo info;
	info.key = KEY;
	info.algVersion = algVersion;

	if(tocken::checkPath(FILEPATH1) == 0)
	{
		info.path = FILEPATH1;
		info.path += FILENAME;

		info.pathCheckCode = FILEPATH1;
		info.pathCheckCode+= FILENAME2;
	}
#ifdef CITOPS
#else
	else if(tocken::checkPath(FILEPATH2) == 0)
	{
		info.path = FILEPATH2;
		info.path += FILENAME;

		info.pathCheckCode = FILEPATH1;
		info.pathCheckCode+= FILENAME2;
	}
	else if(tocken::checkPath(FILEPATH3) == 0)
	{
		info.path = FILEPATH3;
		info.path += FILENAME;

		info.pathCheckCode = FILEPATH1;
		info.pathCheckCode+= FILENAME2;
	}
#endif
	else
	{
		printf("Warning #00001!\n");		//Open file %s failed
		return RET_FAILE_OPEN_ERROR;
	}

	tocken* pTock = tocken::GetInstance(info);
	int r = pTock->getToken();
	if( r != 0)
		return r;							//返回license获取失败原因

	if(tocken::checkCode < 0)				//checkCode小于零，程序启动，更改校验位。
		pTock->setCheckCode(1);

	if(!tocken::isRunning)
		pTock->start();						//启动线程

	int result =  pTock->authenticate(KEY, algVersion);
	return result;							//返回鉴权结果
}

Thread::Thread()
{
}

Thread::~Thread()
{
}

void Thread::start()
{
	pthread_create(&tidRecv, NULL, thread_proxy_func_recv, this) == 0 ? true : false;
	pthread_create(&tidSend, NULL, thread_proxy_func_send, this) == 0 ? true : false;
}

void * Thread::thread_proxy_func_send(void * args)
{
 		Thread * pThread = static_cast<Thread *>(args);
		pThread->runSend();
 		return NULL;
}

void * Thread::thread_proxy_func_recv(void * args)
{
 		Thread * pThread = static_cast<Thread *>(args);
		pThread->runRecv();
 		return NULL;
}

tocken::tocken(){}
tocken::~tocken()
{
	Close();
	tocken::m_pTocken = NULL;
	tocken::isRunning = false;
}

struct tocken::head
{
	head()
	{
		MSGID = 0;
		IMEI = "";
		UUID = "";
		MAC = "";
		SN = 0;
	}

	void _getdata(const char *buf, char * rest)
	{
		char msgID[32] = {0};
		char imei[64] = {0};
		char uuid[32] = {0};
		char mac[32] = {0};
		char sn[64] = {0};
		char add[64] = {0};
		sscanf(buf, "%[^;]%*c%*c%*c%[^;]%*c%*c%*c%[^;]%*c%*c%*c%[^;]%*c%*c%*c%[^;]%*c%*c%*c%[^;]%*c%*c%*c%s", msgID, imei, uuid, mac, sn, add, rest);
		sscanf(msgID, "%d", &MSGID);
		sscanf(sn, "%ld", &SN);
	}

	int	MSGID;
	std::string IMEI;
	std::string UUID;
	std::string MAC;
	long SN;
};

struct tocken::tocken_register
{
	tocken_register()
	{
		company = "";
		deviceType = "";
		algVersion = "";
		company = "";
	}
	int _getdata(char *buf)
	{
		head.MSGID = _tocken_register;
		char n[16] = {0};
		sprintf(n, "%d", head.MSGID);
		std::string str = n;
		char _sn[16] = {0};
		sprintf(_sn, "%ld", head.SN);
		std::string strSN = _sn;

		str += ";;;" + head.IMEI + ";;;" + head.UUID + ";;;" + head.MAC + ";;;" + strSN + ";;;" + ";;;" + company + ";;;" + deviceType + ";;;" + algVersion + ";;;";
		strcpy(buf, str.c_str());

		return strlen(buf);
	}

	struct head head;
	std::string company;
	std::string deviceType;
	std::string algVersion;
};

struct tocken::tocken_register_new
{
	tocken_register_new()
	{
		key = "";
		algVersion = "";
	}
	int _getdata(char *buf)
	{
		head.MSGID = _tocken_register_new;
		char n[16] = {0};
		sprintf(n, "%d", head.MSGID);
		std::string str = n;
		char _sn[16] = {0};
		sprintf(_sn, "%ld", head.SN);
		std::string strSN = _sn;

		str += ";;;" + head.IMEI + ";;;" + head.UUID + ";;;" + head.MAC + ";;;" + strSN + ";;;" + ";;;" + key + ";;;" + algVersion + ";;;";
		strcpy(buf, str.c_str());

		return strlen(buf);
	}

	struct head head;
	std::string key;
	std::string algVersion;
};


struct tocken::tocken_heartbeat
{
	tocken_heartbeat(){}
	int _getdata(char *buf)
	{
		head.MSGID = _tocken_heartbeat;
		char n[16] = {0};
		sprintf(n, "%d", head.MSGID);
		std::string str = n;
		char _sn[16] = {0};
		sprintf(_sn, "%ld", head.SN);
		std::string strSN = _sn;

		str += ";;;" + head.IMEI + ";;;" + head.UUID + ";;;" + head.MAC + ";;;" + strSN + ";;;" + IMEI + "," + CIMI + ";;;";
		strcpy(buf, str.c_str());

		return strlen(buf);
	}
	struct head head;
	std::string IMEI;
	std::string CIMI;
};

struct tocken::tocken_srv_check
{
	tocken_srv_check()
	{
	}
	int _getdata(char *buf)
	{
		head.MSGID = _tocken_srv_check;
		char n[16] = {0};
		sprintf(n, "%d", head.MSGID);
		std::string str = n;
		char _sn[16] = {0};
		sprintf(_sn, "%ld", head.SN);
		std::string strSN = _sn;

		str += ";;;" + head.IMEI + ";;;" + head.UUID + ";;;" + head.MAC + ";;;" + strSN + ";;;" + ";;;" + token + ";;;";
		strcpy(buf, str.c_str());

		return strlen(buf);
	}

	struct head head;
	std::string token;
};

struct tocken::tocken_srv_check_resp
{

};

int tocken::authenticate(std::string key, std::string algVersion)
{
	pthread_mutex_lock(&m_lock);

	int result = checkCheckCode();
	if(result != 0)
	{
		pthread_mutex_unlock(&m_lock);
		return result;
	}

	m_info.algVersion = algVersion;
	int n = 0;
	while(n < 1)
	{
		FILE *fp = NULL;
		char buff[256] = {0};
		fp = fopen(m_info.path.c_str(), "r");
		if(fp != NULL)
		{
			fgets(buff, 255, (FILE*)fp);
			fclose(fp);
			int len = strlen(buff);
			if(len > 0)
			{
				//md5
				//Md5Encode encode_obj;

				//对数据进行sha512算法摘要
				SHA512_CTX c;
				unsigned char md[SHA512_DIGEST_LENGTH];

				std::string malgVersion;

				int pos = 0;
				switch(buff[len - 1])
				{
				case '1':
					malgVersion = "ALL";
					break;
				case '2':
					malgVersion = m_info.algVersion;
					break;
				case '3':
					pos = m_info.algVersion.find("_"); //单个下划线'_'分割字符串，第0个为产品类型
					malgVersion = m_info.algVersion.substr(0, pos);
					break;
				default:
					break;
				}

#ifdef CIMI
				//std::string ret = encode_obj.Encode(m_IMEI + m_CIMI + m_info.key + malgVersion);
				std::string ret = m_IMEI + m_CIMI + key + malgVersion;
#else
				//std::string ret = encode_obj.Encode(m_IMEI + m_info.key + malgVersion);
				std::string ret = m_IMEI + key + malgVersion;
#endif
				const char *ct = ret.c_str();
				SHA512((unsigned char *)ct, strlen(ct), md);

				char result[256] = {0};
				int i = 0;
			    for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
				{
					sprintf(&result[2 * i], "%02x", md[i]);
				}

				buff[len - 1] = '\0';
				if(strcmp(buff, result) == 0)
				{
					printf("Authenticate success!\n");
					pthread_mutex_unlock(&m_lock);
					return RET_SUCCESS;
				}
			}
		}
		//usleep(1000000);
		n++;
	}

	printf("Authenticate failed!\n");
	pthread_mutex_unlock(&m_lock);

	return RET_FAIL;
}

int tocken::getToken()
{
	int n = 0;
	int result = -1;
	char buf[MAXLINE];
	char recvBuf[MAXLINE];

	//get IMEI
	char tempIMEI[256] = {0};
	strcpy(tempIMEI, get_imei(0));
	if (strlen(tempIMEI) == 0) {
		printf("ERROR #00000");
		return RET_FAIL_IMEI;
	}

	m_IMEI = tempIMEI;
	//m_IMEI = "cfaaqqa";

	// get CIMI
#ifdef CIMI
	if (get_imei(1) == NULL) {
		printf("ERROR #00001");
		return RET_FAIL_IMEI;
	}
	m_CIMI = get_imei(1);
#else
		m_CIMI = "";
#endif

	//m_ICCID
	//m_ICCID = get_imei(2);

	// get UUID
	m_UUID = "00001";

	// get mac address
	char mac[32];
	memset(mac, 0, sizeof(mac));
	int rc = netdev_get_mac("eth0", mac, sizeof(mac));
	m_MAC = mac;
	struct tocken_register_new out;
#ifdef CIMI
	out.head.IMEI = m_IMEI + m_CIMI;
#else
	out.head.IMEI = m_IMEI;
#endif
	out.head.UUID = m_UUID;
	out.head.MAC = m_MAC;
	out.head.SN = getSN();
	out.algVersion = m_info.algVersion;
	out.key = m_info.key;
	out._getdata(buf);

	std::string sendmsg = buf;
	encrypt(buf, sendmsg);

	//读取鉴权文件，如果没有，进行注册，获取鉴权码
	bool isRegister = true;
	pthread_mutex_lock(&m_lock);
    FILE *fp = NULL;
    char buff[255];
    fp = fopen(m_info.path.c_str(), "r");

    if(fp != NULL)
    {
    	fgets(buff, 255, (FILE*)fp);
    	int len = strlen(buff);
    	//去掉最后的换行符
		if(buff[len-1] == '\n')
		{
			len--;
			buff[len] = 0;
		}
    	if(strlen(buff) > 0)
    	{
    		isRegister = false;
    	}
		else
		{
			std::cout << "No license!" << std::endl;
		}
    	fclose(fp);
    }
    pthread_mutex_unlock(&m_lock);
    if(!isRegister)										//	鉴权文件已存在
    	return 0;

    // 首次鉴权，重复连接服务器，直至成功连接，获取和保存鉴权码。
	char ip[32] = {0};
	int l = sizeof(DSIP) / sizeof(char*);
	m_info.ip = DSIP[l - 1];
	for(int i = 0; i < l - 1; i++)
	{
		if(socket_resolver(DSIP[i], ip, sizeof(ip)) == 0)
		{
			m_info.ip = ip;
			break;
		}
	}

    ReConnect(0);
	while(isRegister)
	{
		if(Send(sendmsg.c_str(), strlen(buf)))
		{
			n = Recv(recvBuf, MAXLINE);
			std::string recvMsg = recvBuf;
			decrypt(recvBuf, recvMsg);

			if(n > 0)
			{
				char rest[256] = {0};
				struct head head;
				head._getdata(recvMsg.c_str(), rest);

				if(head.MSGID == _tocken_register_resp)
				{
					char flag[8] = {0};
					char tocken[64] = {0};

					sscanf(rest, "%[^;]%*c%*c%*c%[^;]%*c%*c%*c", flag, tocken);
					result = atoi(flag);
					if(result == 0 || result == 1)
					{
						printf("Register success!\n");
						saveTocken(tocken);
						isRegister = false;

						//获取注册码成功后，根据系统时间和校验位，创建校验文件
						srand((int)time(0));
						tocken::checkCode = rand()%1000;
						setCheckCode(0);
						break;
					}
					else
					{
						printf("Register failed, error number: %d. \n", result);
						break;

					}
				}
			}
		}
		else
		{
			ReConnect(0);
		}
		usleep(500000);
	}

	Close();

    if(!isRegister)
    	return 0;
    return result;
}

void tocken::init(authenticateInfo &info)
{
	m_info = info;
	m_nSockFd = 0;
	m_sn = 0;
	m_disconnectSec = 0;
}

void tocken::setCheckCode(int type)
{
    struct timeval tv;
	gettimeofday(&tv, NULL);
	long long sec = tv.tv_sec;
	char raw[64] = {0};
	sprintf(raw, "%lld", sec);

	if(type == 0) //已经设置了随机数，是注册成功后或者服务器回应，重新设置日期和校验位。
	{
		char strCheckCode[16] = {0};
		sprintf(strCheckCode, "%lld", tocken::checkCode);
		strcat(raw, strCheckCode);

		FILE *fp = NULL;
		fp = fopen(m_info.pathCheckCode.c_str(), "w+");
		int padding_size = 0;
		char *after_padding_buf = NULL;
		char encrypt_buf[128] = {0};
		if(fp != NULL)
		{
			after_padding_buf = padding_buf(raw, (int)strlen(raw), &padding_size);
			encrpyt_buf(after_padding_buf, encrypt_buf, padding_size);

	    	fprintf_buff(encrypt_buf, padding_size, fp);
	    	free(after_padding_buf);
	    	fclose(fp);
		}
	}
	else if(type == 1 || type == 2)//1：在已经有校验文件情况下，程序启动，随机初始化校验位，生成新的校验文件。2：进程运行，定时修改校验位并生成新的校验文件。
	{
		if(type == 1)
		{
			srand((int)time(0));
			tocken::checkCode = rand()%1000;
		}

		char strCheckCode[16] = {0};
		sprintf(strCheckCode, "%lld", tocken::checkCode);
		strcat(raw, strCheckCode);

		//读取校验文件并解密获得校验值，截取日期后和新的校验值合并，获得新的校验值。
		FILE *fp = NULL;
		char buff2[128] = {0};
		char new_buf[128] = {0};
		fp = fopen(m_info.pathCheckCode.c_str(), "r");
		if(fp != NULL)
		{
			fgets(buff2, 128, (FILE*)fp);
			if(strlen(buff2) < 10)
			{
				fclose(fp);
				return;
			}
		    unsigned char temp[128] = {0};
		    unsigned int tempLen = 0;
		    int len = hex2str(buff2, temp, &tempLen);

			char decrypt_buf[128] = {0};
			decrpyt_buf((char *)temp, decrypt_buf, len);

			strncpy(new_buf, decrypt_buf, 10);
			strcat(new_buf, strCheckCode);

			fclose(fp);
			fp = NULL;
		}
		else
		{
			return;
		}

		//重新写入新的校验值
		fp = fopen(m_info.pathCheckCode.c_str(), "w+");
		int padding_size = 0;
		char *after_padding_buf = NULL;
		char encrypt_buf[128] = {0};
		if(fp != NULL)
		{
			after_padding_buf = padding_buf(new_buf, (int)strlen(new_buf), &padding_size);
			encrpyt_buf(after_padding_buf, encrypt_buf, padding_size);

	    	fprintf_buff(encrypt_buf, padding_size, fp);
	    	free(after_padding_buf);
	    	fclose(fp);
		}
	}
}

int tocken::checkCheckCode()
{
	int result = 0;
	FILE *fp = NULL;
	char buff2[128] = {0};
	char new_buf[128] = {0};
	char strCode[16] = {0};
	fp = fopen(m_info.pathCheckCode.c_str(), "r");
	if(fp != NULL)
	{
		fgets(buff2, 128, (FILE*)fp);
		if(strlen(buff2) < 10)
		{
			fclose(fp);
			return RET_FAILE_CHECKCODE_FAUILE;
		}
	    unsigned char temp[128] = {0};
	    unsigned int tempLen = 0;
	    int len = hex2str(buff2, temp, &tempLen);

		char decrypt_buf[128] = {0};
		decrpyt_buf((char *)temp, decrypt_buf, len);

		strncpy(new_buf, decrypt_buf, 10);
		strncpy(strCode, decrypt_buf + 10, strlen(decrypt_buf) - 10);

		long long times;
		long long code;
		sscanf(new_buf, "%lld", &times);
		sscanf(strCode, "%lld", &code);

	    struct timeval tv;
		gettimeofday(&tv,NULL);
		long long sec = tv.tv_sec;

		//校验离线时间是否超过7天
		if(sec - times < 0 || sec - times > OVERTIME)
		{
			result = RET_FAILE_CHECKCODE_OVERTIME;
			remove(m_info.path.c_str());
		}

		//检查校验位是否正确
		if(tocken::checkCode - code < -6 || tocken::checkCode - code > 6)
		{
			result = RET_FAILE_CHECKCODE_BIT_FAUILE;
			remove(m_info.path.c_str());
		}

		fclose(fp);
		fp = NULL;
	}
	else
	{
		remove(m_info.path.c_str());
		return RET_FAILE_CHECKCODE_WITHOUT;
	}

	return result;
}

int tocken::CreateTcpSocket()
{
	m_nSockFd = socket(AF_INET, SOCK_STREAM, 0);
	if(m_nSockFd == -1)
		return -1;

	struct timeval tv_timeout;
	tv_timeout.tv_sec = 10;
	tv_timeout.tv_usec = 0;
	setsockopt(m_nSockFd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_timeout, sizeof(struct timeval));

	m_serverAddr.sin_family = AF_INET;
	m_serverAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, m_info.ip.c_str(), &m_serverAddr.sin_addr.s_addr);
	return 0;
}

int tocken::Recv(char* pBuf, int nLen)
{
	int nNumbytes;
	nNumbytes = recv(m_nSockFd, pBuf, nLen, 0);

	if(nNumbytes == -1)
	{
		return -1;
	}

	return nNumbytes;
}

void tocken::Close()
{
	if( m_nSockFd > 0)
	{
		close(m_nSockFd);
		m_nSockFd = 0;
	}
}

int tocken::Send(const char* pBuf, int nLen)
{
	return send(m_nSockFd, pBuf, nLen, 0);
}

bool tocken::Connect()
{
	if(connect(m_nSockFd,(struct sockaddr *)&m_serverAddr, sizeof(m_serverAddr)) == -1)
	{
		return false;
	}

	return true;
}

bool tocken::ReConnect(int n)
{
	int i = 0;
	while(n == 0 || i < n)
	{
		Close();
		CreateTcpSocket();
		if(Connect())
			return true;

		i++;
		if(n == 0)
			printf("Connecting Service!!!\n");
		usleep(1000000);
	}

	Close();
	return false;
}

void tocken::runSend()
{
	tocken::isRunning = true;
	int count = 0;
	char buf[MAXLINE];
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		struct head head;
#ifdef CIMI
		head.IMEI = m_IMEI + m_CIMI;
#else
		head.IMEI = m_IMEI;
#endif
		head.UUID = m_UUID;
		head.MAC = m_MAC;

		if((count % 300) == 0)		//每五分钟，向服务端发送终端鉴权校验请求
		{
			FILE *fp = NULL;
			char token[256] = {0};
			fp = fopen(m_info.path.c_str(), "r");
			if(fp != NULL)
			{
				fgets(token, 255, (FILE*)fp);
				fclose(fp);
			}

			head.SN = getSN();
			struct tocken_srv_check srv_check;
			srv_check.head = head;
			srv_check.token = token;
			srv_check._getdata(buf);
		}

		if((count % 30) == 0)	//每30秒,验证位改变
		{
			tocken::checkCode++;
			setCheckCode(2);
		}

		if(count >= 900)	//每15分钟,心跳包
		{
			head.SN = getSN();

			struct tocken_heartbeat heartbeat;
			heartbeat.head = head;
			heartbeat.IMEI = m_IMEI;
			heartbeat.CIMI = m_CIMI;
			heartbeat._getdata(buf);
			count = 0;
		}

		std::string msg = buf;
		encrypt(buf, msg);
		if(strlen(buf) > 0)
		{
			Send(msg.c_str(), strlen(buf));
#ifdef DEBUG
			LOG("Send: %s\n", buf);
#endif
		}

		count++;
		pthread_mutex_lock(&m_lockSec);
		m_disconnectSec++;
		pthread_mutex_unlock(&m_lockSec);

		usleep(1000000);
	}

	tocken::isRunning = false;
}

void tocken::runRecv()
{
	tocken::isRunning = true;
	char buf[MAXLINE];

	char ip[32] = {0};
	int l = sizeof(DSIP) / sizeof(char*);
	m_info.ip = DSIP[l - 1];
	for(int i = 0; i < l - 1; i++)
	{
		if(socket_resolver(DSIP[i], ip, sizeof(ip)) == 0)
		{
			m_info.ip = ip;
			break;
		}
	}

	//重复连接服务器，直到连接成功为止
	do
	{
		usleep(500000);
		Close();
		CreateTcpSocket();
	}while(!Connect());

	int cnt;
	char pBuf[MAXLINE] = {0};
	while(1)
	{
		memset(pBuf, 0, sizeof(pBuf));
	    cnt = (int)Recv(pBuf, MAXLINE);

		std::string recvMsg = pBuf;
		decrypt(pBuf, recvMsg);

	    if(cnt >0)
	    {
			pthread_mutex_lock(&m_lockSec);
			m_disconnectSec = 0;
			pthread_mutex_unlock(&m_lockSec);

			char rest[256] = {0};
			struct head head;
			head._getdata(recvMsg.c_str(), rest);

#ifdef DEBUG
			LOG("Recv MSGID: %#X, %s\n", head.MSGID, rest);
#endif

			if(head.MSGID == _tocken_srv_resp)	//通用应答
			{
				char respSN[16] = {0};
				char respMSGID[16] = {0};
				char respResult[8] = {0};
				sscanf(rest, "%[^;]%*c%*c%*c%[^;]%*c%*c%*c[^;]%*c%*c%*c", respSN, respMSGID, respResult);

				long SN = 0;
				int msgID = 0;
				int result;
				SN = atol(respSN);
				msgID = atoi(respMSGID);
				result = atoi(respResult);
				switch(msgID)
				{
				case _tocken_srv_check:		//服务器连接验证
					if(result == 0)
						setCheckCode(0);
					break;
				}
			}
	    }
	    else
	   {
	    	if(m_disconnectSec > 30 * 60)
	    	{
				if(!ReConnect(100))
					usleep(600000000);	// 连接服务器失败后，10分钟后再尝试重连！
	    	}

	        if((cnt<0) &&(errno == EAGAIN||errno == EWOULDBLOCK||errno == EINTR))
	        {
	            continue;//继续接收数据
	        }
	        else
	        {
				if(!ReConnect(100))
					usleep(600000000);	// 连接服务器失败后，10分钟后再尝试重连！
	        }
	    }

	    usleep(1000000);
	}

	Close();
	tocken::isRunning = false;
}

void tocken::saveTocken(char* buf)
{
	pthread_mutex_lock(&m_lock);
	FILE *fp = NULL;
    fp = fopen(m_info.path.c_str(), "w+");
    if(fp != NULL)
    {
    	fputs(buf, fp);
    	fclose(fp);
    }
    pthread_mutex_unlock(&m_lock);
}

int tocken::netdev_get_mac(const char *devname, OUT char *macstr, int macstr_len)
{
	int sock;
	struct ifreq ifaddr;
	struct in_addr __sin_addr;
	int rc;

	if ( devname == NULL || *devname == 0 )
		devname = "eth0";

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sock < 0 )
		return -1;

	rc = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK); // nonblock, 如果不设置可能会一直阻塞

	memset(&ifaddr, 0, sizeof(ifaddr));
	snprintf(ifaddr.ifr_name, sizeof(ifaddr.ifr_name), devname);

	rc = ioctl(sock, SIOCGIFHWADDR, &ifaddr);
	if ( rc >= 0 )
	{
		unsigned char mac[6];
		memcpy(mac, ifaddr.ifr_hwaddr.sa_data, 6);
		snprintf(macstr, macstr_len, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else
	{
		printf("get mac error, %d, %s\n", errno, strerror(errno));
	}


	close(sock);
	return rc;
}

long tocken::getSN()
{
	return m_sn++;
}

int tocken::checkPath(const char * p)
{
	//检测文件夹是否可以写
	pthread_mutex_lock(&m_lock);
	int result = -1;
	if(access(p, F_OK) != 0)
	{
		CreateDirectoryEx(p);
	}
    result = access(p, W_OK);
	pthread_mutex_unlock(&m_lock);

	return result;
}
