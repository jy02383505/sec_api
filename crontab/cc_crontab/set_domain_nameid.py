# coding=utf-8
import os
import sys
import uuid
import json
import time
import base64
import datetime
import requests

sys.path.append(
    os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))

from mongo_db import (conn_domain_mongo, conn_cc_domain_task_mongo,
                      conn_domain_cname_mongo)

from util import datetime_to_timestamp


def link(url, method, headers, body=''):
    print(url)
    response = None

    for i in range(3):
        try:
            if method == 'POST':
                response = requests.post(
                    url, data=body, headers=headers, timeout=60)

            elif method == 'GET':
                response = requests.get(url, headers=headers, timeout=60)
            elif method == 'PUT':
                response = requests.put(
                    url, data=body, headers=headers, timeout=60)

            if response:
                return response

        except Exception as e:
            time.sleep(1)
            print('请求超时，第%s次重复请求' % (i+1), e)
            pass
    else:
        return -1

def get_domain_cname(channel):
    """获取域名cname"""

    params = {
        "ROOT": {
            "BODY": {
                "BUSI_INFO": {
                    "CHN_NAME": channel
                }
            },
            "HEADER": {
                "AUTH_INFO": {
                    "FUNC_CODE": "9042",
                    "LOGIN_NO": "novacdn",
                    "LOGIN_PWD": "",
                    "OP_NOTE": "",

                }
            }
        }

    }

    headers = {
        "Content-type": "application/json"
    }

    url = 'http://cms3-apir.chinacache.com/apir/9040/qryCName'

    params = json.dumps(params)
    print(params)
    body = params.encode()
    response = link(url, 'POST', headers, body=body)
    """
    {
        'ROOT': {
            'HEADER': {},
            'BODY': {
                'OUT_DATA': {
                    'cname': 'lxcc.itestxz0013.chinacache.com.ccgslb.com.cn'
                },
                'RETURN_CODE': '0',
                'RETURN_MSG': 'OK'
            }
        }
    }
    """
    res = response.json()
    print(res)
    cname = res.get('ROOT', {}).get(
        'BODY', {}).get('OUT_DATA', {}).get('cname', '')

    return cname

def handle_name_id(domain, inner_cname, other_cname):
    """
    处理cname
    :param domain: 域名
    :param inner_cname: 各厂家cname
    :param other_cname: 融合统一对外cname
    :return: True or False
    """
    cname_db = conn_domain_cname_mongo()
    filter_opt = {"domain": domain, "location": "default"}

    # 创建name_id 对象
    cname_obj = cname_db.find_one(filter_opt)

    if not cname_obj:
        inner_cname_str = ",".join([inner_cname])

        data = {
            "domain": domain,
            "inner_cname": inner_cname_str,
            "other_cname": other_cname,
            "location": "default",
            "add_time": datetime.datetime.now(),
        }
        cname_db.insert(data)

    else:
        inner_cname_str = cname_obj.get('inner_cname', '')
        update_doc = {
            'inner_cname': inner_cname_str
        }

        cname_db.update(filter_opt, {'$set': update_doc})

    base_msg = "default;true;%s;;;;;;120" % inner_cname_str

    base_msg = base_msg.lower()
    print(111111111, base_msg)
    message = base64.b64encode(base_msg.encode()).decode('utf-8')

    body = {
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
                        "message": message,
                        "type": "add"
                    }]
                }]
            }
        }
    }

    print(body)

    params = json.dumps(body)
    body = params.encode()

    print('*****send dlc to 223.203.98.195')
    url = 'http://223.203.98.195:8030/dlc/router/fusion_cmd/'
    """
    {
        'ROOT': {
            'HEADER': {},
            'BODY': {
                'list': [{
                    'msg': 'ok',
                    'result': 1,
                    'hostname': 'BGP-SM-4-3gA',
                    'backTime': '20190820161314',
                    'taskLineId': '24715b79-1bc9-43f5-818d-1513c962185e'
                }]
            }
        }
    }
    """
    ret = {}
    send_result = False
    try:
        ret = link(url, 'POST', {}, body)
        if ret == -1:
            assert False
    except Exception as e:
        error_msg = "下发nameid任务失败 %s %s %s" % (
            e, body, "223.203.98.195")
        print(error_msg)

    print('*****send dlc to 223.202.202.16')
    url = 'http://223.202.202.16:8030/dlc/router/fusion_cmd/'
    try:
        ret = link(url, 'POST', {}, body)

        if ret == -1:
            assert False
        print(ret.json())
    except Exception as e:
        error_msg = "下发nameid任务失败 %s %s %s" % (
            e, body, "223.202.202.16")
        print(error_msg)

    try:
        ret = ret.json()
        result = ret.get('ROOT', {}).get(
            'BODY', {}).get('list', [])[0]['result']
    except Exception as e:
        print(e)

    if result == 1:
        send_result = True

    return send_result

if __name__ == '__main__':
    domain = 'novatest05.ccindexnoicp.cn'

    channel = 'http://%s' % domain

    cname = get_domain_cname(channel)

    inner_cname = get_domain_cname(channel)

    other_cname = '%s.ns.xgslb.com' % domain
    handle_name_id(domain, inner_cname, other_cname)
