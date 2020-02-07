#ifndef _TOCKEN_H_
#define _TOCKEN_H_
#include <iostream>

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

int authentication(std::string key, std::string algVersion); // key： 用户申请id+key   algVersion：算法版本         函数返回0，为成功

#endif
