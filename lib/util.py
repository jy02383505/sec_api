

import time
import uuid
import json
import base64
import aiohttp
import hashlib
import datetime

from aiohttp import TCPConnector
from sanic.log import logger

from config import NSQ_HOST


async def web_link(url, headers=None, body=None, method='POST', timeout=300):
    res = {}
    code = 0
    # try:
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
            timeout=timeout_obj, headers=headers,
            connector=TCPConnector(verify_ssl=False)) as session:

        if method == 'POST':
            async with session.post(url, json=body) as response:
                res = await response.json()
        elif method == 'GET':
            async with session.get(url) as response:
                res = await response.json()
        elif method == 'PUT':
            async with session.put(url, data=body) as response:
                res = await response.json()

        elif method == 'DELETE':
            async with session.delete(url, data=body) as response:
                res = await response.json()

        if isinstance(res, str):
            res = json.loads(res)
        code = 1
    # except Exception as e:
    #     logger.info(e)

    return code, res


def str_to_datetime(time_str, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param time_str: 2016-01-01 00：00：00
    :param _format: 时间格式 %Y-%m-%d %H:%M:%S
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    temp_time = time.strptime(time_str, _format)
    result_datetime = datetime.datetime(*temp_time[:6])
    return result_datetime


def datetime_to_str(date_time, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param date_time: datetime.datetime(2016, 1, 1, 0, 0, 0)
    :param _format: 时间格式 %Y-%m-%d %H:%M:%S
    :return: 2016-01-01 00：00：00
    """
    return date_time.strftime(_format)


def datetime_to_timestamp(date_time):
    """
    :param date_time: datetime.datetime(2016, 1, 1, 0, 0, 0)
    :return: 1451577600
    """
    return int(time.mktime(date_time.timetuple()))


def timestamp_to_datetime(timestamp):
    """
    :param timestamp: 1451577600
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    return datetime.datetime.fromtimestamp(timestamp)


def timestamp_to_str(timestamp, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param timestamp: 1451577600
    :param _format: 时间格式 %Y-%m-%d %H:%M:%S
    :return: 2016-01-01 00：00：00
    """
    return time.strftime(_format, time.localtime(timestamp))


def str_to_timestamp(time_str, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param time_str: 2016-01-01 00：00：00
    :param _format: 时间格式 %Y-%m-%d %H:%M:%S
    :return: 1451577600
    """
    return int(time.mktime(time.strptime(time_str, _format)))


def datetime_correction(_datetime, fix=15):
    """
    时间修正
    :param _datetime: 需要修正的时间datetime.datetime(2016, 1, 1, 0, 4, 0)
    :param fix: 修正系数
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    target_time = datetime.datetime(_datetime.year, _datetime.month,
                                    _datetime.day, _datetime.hour,
                                    _datetime.minute)

    if (target_time.minute % fix) != 0:
        sub = target_time.minute % fix
        target_time -= datetime.timedelta(minutes=sub)

    return target_time


def get_time_interval(start_time, end_time, interval=15):
    """
    时间需要修正后的时间
    :param start_time: datetime.datetime(2016, 1, 1, 0, 0, 0)
    :param end_time: datetime.datetime(2016, 1, 1, 1, 0, 0)
    :param interval: 间隔时间
    :return: [
        datetime.datetime(2016, 1, 1, 0, 0, 0),
        datetime.datetime(2016, 1, 1, 0, 15, 0),
            .
            .
        datetime.datetime(2016, 1, 1, 1, 0, 0)]
    """
    time_list = []
    while start_time <= end_time:
        time_list.append(start_time)
        start_time += datetime.timedelta(minutes=interval)

    return time_list


def get_time_list(start_time, end_time, _format='%Y-%m-%d %H:%M'):
    """获取时间范围内时间节点"""
    if _format == '%Y-%m-%d %H:00':
        step = 3600
    elif _format == '%Y-%m-%d 00:00':
        step = 3600 * 24
    else:
        step = 300

    time_list = []
    for t in range(start_time, end_time+300, step):
        time_list.append(timestamp_to_str(t, _format=_format))

    return time_list


def get_day_list(date_time, fix=5):
    """获取颗粒时间列表"""
    num = 288
    day_list = []
    for i in range(0, num):
        day_list.append(date_time)
        date_time += datetime.timedelta(minutes=fix)

    return day_list


def get_md5_flag():
    """用时间生成md5标识"""
    hash_lib = hashlib.md5()
    sec_str = str(time.time())
    hash_lib.update(sec_str.encode())
    return hash_lib.hexdigest()


async def nsq_writer(nsq_name, nsq_params):
    """创建nsq writer"""
    from asyncnsq import create_writer
    send_flag = False
    for i in NSQ_HOST:
        try:
            writer = await create_writer(host=i)
            await writer.pub(nsq_name, nsq_params.encode())
            send_flag = True
            break
        except Exception as e:
            logger.info(e)

    return send_flag


async def get_domain_status(domain, cdn_opt, mongodb):
    """domain 状态"""
    domain_status = []
    for opt in cdn_opt:
        opt_db = eval('mongodb.%s_CDN_domain_info' % opt)

        opt_search_sql = {
            'domain': domain
        }

        async for opt_d in opt_db.find(opt_search_sql):
            domain_status.append(opt_d.get('status'))

    return domain_status


async def sync_dns_del(domain, cname_db):
    """同步dns"""
    search_sql = {
        'domain': domain
    }

    cname_doc = await cname_db.find_one(search_sql)

    send_result = {}

    if cname_doc:
        inner_cname = cname_doc.get('inner_cname', '')
        other_cname = cname_doc.get('other_cname', '')
        message = "default;true;%s;;;;;;120" % ",".join([inner_cname])

        params = {
            "ROOT": {
                "HEADER": {
                    "ISCOMPRESS": False,
                    "OPERTYPE": "RESET",
                    "OPERBUSI": False
                },
                "BODY": {
                    "taskLineId": str(uuid.uuid4()),
                    "datas": [{
                        "busiType": "cdnService",
                        "opers": [{
                            "name": other_cname,
                            "message": base64.b64encode(
                                message.encode()).decode('utf-8'),
                            "type": "del"
                        }]
                    }]
                }
            }
        }
        print(params)
        try:
            url = 'http://223.203.98.195:8030/dlc/router/fusion_cmd/'
            code, result = await web_link(url, body=params,  method='POST')
            assert code

            send_result = result

        except AssertionError:
            url = 'http://223.202.202.16:8030/dlc/router/fusion_cmd/'
            _, result = await web_link(url, body=params, method='POST')
            send_result = result

    return send_result
