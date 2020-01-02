# -*- coding:utf-8 -*-
"""
融合api一些常量信息
方便统一各厂商api返回数值
"""


class FuseApiConfig(object):
    """
    各厂商通用api配置
    """
    OTHER = 'other'

    SEND_SUCCESS = 1    # api任务下发成功
    SEND_FAIL = 2    # api任务下发失败
    SEND_TIMEOUT = 3  # api任务下发超时

    REFRESH_CONDUCT = 0    # 刷新进行
    REFRESH_SUCCESS = 1    # 刷新成功
    REFRESH_FAIL = 2    # 刷新失败

    REFRESH_CONF = {
        'cc_contrast': {
            'UNKNOWN': REFRESH_CONDUCT,
            'SUCCESS': REFRESH_SUCCESS,
            'FAIL': REFRESH_FAIL
        },
    }

    PRELOAD_CONDUCT = 0    # 预加载进行
    PRELOAD_SUCCESS = 1    # 预加载成功
    PRELOAD_FAIL = 2    # 预加载失败

    PRELOAD_CONF = {
        'cc_contrast': {
            'TIMER': PRELOAD_CONDUCT,
            'PROGRESS': PRELOAD_CONDUCT,
            'INVAALID': PRELOAD_CONDUCT,
            'FINISHED': PRELOAD_SUCCESS,
            'FAILED': PRELOAD_FAIL
        },
        'tencent_contrast': {
            'init': PRELOAD_CONDUCT,
            'process': PRELOAD_CONDUCT,
            'done': PRELOAD_SUCCESS,
            'fail': PRELOAD_FAIL
        },
    }

    STATUS_CODES = {
        # 状态码返回格式
        'key_rule': ['200', '206', '302', '304', '403', '404', '5xx', OTHER],
        # 常规使用的状态码key
        'routine_keys': ['200', '206', '302', '304', '403', '404'],
        # 错误状态码key
        'error_key': '5xx',
        # 错误状态码标志
        'error_flag': '5'
    }

    AREA_REQUESTS = {
        # 区域请求数格式
        'key_rule': [
            '广东省', '安徽省', '山东省', '江苏省', '贵州省', '辽宁省', '四川省',
            '河北省', '吉林省', '云南省', '青海省', '河南省', '湖北省', '浙江省',
            '湖南省', '福建省', '黑龙江省', '陕西省', '山西省', '江西省', '甘肃省',
            '海南省', '重庆', '北京', '天津', '上海', '西藏', '新疆', '广西',
            '宁夏', '内蒙古', OTHER
        ],
        # tencent 区域对照
        'tencent_area_dic': {
            '广东': '广东省',
            '安徽': '安徽省',
            '山东': '山东省',
            '江苏': '江苏省',
            '贵州': '贵州省',
            '辽宁': '辽宁省',
            '四川': '四川省',
            '河北': '河北省',
            '吉林': '吉林省',
            '云南': '云南省',
            '青海': '青海省',
            '河南': '河南省',
            '湖北': '湖北省',
            '浙江': '浙江省',
            '湖南': '湖南省',
            '福建': '福建省',
            '黑龙江': '黑龙江省',
            '陕西': '陕西省',
            '山西': '山西省',
            '江西': '江西省',
            '甘肃': '甘肃省',
            '海南': '海南省',
            '重庆': '重庆',
            '北京': '北京',
            '天津': '天津',
            '上海': '上海',
            '西藏': '西藏',
            '新疆': '新疆',
            '广西': '广西',
            '宁夏': '宁夏',
            '内蒙古': '内蒙古',
        },

        'cc_area_dict': {
            '河北省': 'hebei',
            '宁夏': 'ningxia',
            '贵州省': 'guizhou',
            '新疆': 'xinjiang',
            '北京': 'beijing',
            '福建省': 'fujian',
            '海南省': 'hainan',
            '黑龙江省': 'heilongjiang',
            '广东省': 'guangdong',
            '广西': 'guangxi',
            '浙江省': 'zhejiang',
            '青海省': 'qinghai',
            '江苏省': 'jiangsu',
            '山西省': 'shanxi',
            '河南省': 'henan',
            '云南省': 'yunnan',
            '西藏': 'xizang',
            '辽宁省': 'liaoning',
            '湖南省': 'hunan',
            '其他': 'xianggang',
            '陕西省': 'shaanxi',
            '安徽省': 'anhui',
            '天津': 'tianjin',
            '江西省': 'jiangxi',
            '湖北省': 'hubei',
            '重庆': 'chongqing',
            '甘肃省': 'gansu',
            '台湾省': 'taiwan',
            '山东省': 'shandong',
            '吉林省': 'jilin',
            '上海': 'shanghai',
            '四川省': 'sichuan',
            '内蒙古': 'neimenggu'
        },

    }
    # 运营商对照
    ISP_REQUESTS = {
        # isp请求数格式
        'key_rule': [
            '中国电信', '中国联通', '中国移动', '教育网',
            '中国铁通', '其他', '长城宽带', OTHER
        ],

        'cc_isp_dic': {
            '中国移动': 'mobile',
            '中国电信': 'telecom',
            '中国联通': 'unicom',
            '中国网通': 'cncnet',
            '中国铁通': 'tietong',
            '教育网': 'cernet',
            '长城宽带': 'drpeng',
            'CKL南京移动合作': 'mobile',
            '台湾移动': 'mobile',
            '慈溪移动': 'mobile',
            '阿里移动': 'mobile',
            '逸云移动': 'mobile',
            '翌旭移动': 'mobile',
            '音信移动': 'mobile',
            '优刻得移动': 'mobile',
            '网鼎移动': 'mobile',
            '电信通': 'telecom',
            '日本电信电话': 'telecom',
            '台湾中华电信': 'telecom',
            '中国电信自建': 'telecom',
            '新加坡电信': 'telecom',
            '信威(柬埔寨)电信有限公司': 'telecom',
            '格洛布电信': 'telecom',
            'Jasmine电信系统': 'telecom',
            '卡塔尔电信': 'telecom',
            '印尼电信': 'telecom',
            '中国电信': 'telecom',
            '马来西亚电信': 'telecom',
            '阿里电信': 'telecom',
            '平安电信': 'telecom',
            '55电信': 'telecom',
            '逸云电信': 'telecom',
            '京东电信': 'telecom',
            '指南针电信': 'telecom',
            '广讯电信': 'telecom',
            '翌旭电信': 'telecom',
            '慈溪电信': 'telecom',
            '哈尔滨电信': 'telecom',
            '阿里联通': 'unicom',
            '京东联通': 'unicom',
            '平安联通': 'unicom',
            '55联通': 'unicom',
            '逸云联通': 'unicom',
            '硕软联通': 'unicom',
            '广讯联通': 'unicom',
            '音信联通': 'unicom',
            '翌旭联通': 'unicom',
            '慈溪联通': 'unicom',
            '中国铁通': 'tietong',
            '中国铁通2号': 'tietong',
        },

    }


