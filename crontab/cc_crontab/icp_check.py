# -*- coding: utf-8 -*-
"""
如果ICP有效，解析到国内边缘hpc100-01-mix.ccna.ccgslb.com.cn
如果无效，解析到海外的RIM边缘hpc100-RIM.ccna.ccgslb.com.cn
即解析按照融合的ns.xgslb.com->ccgslb.com->国内边缘/RIM边缘(每天定时切换)
"""
import os
import sys
import uuid
import time
import json
import base64
import requests

from cc_api import CCAPI
from mongo_db import conn_user_db, conn_domain_mongo, conn_domain_cname_mongo

sys.path.append(
    os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))

RIM_CNAME = 'hpc100-RIM.ccna.ccgslb.com.cn'
MIX_CNAME = 'hpc100-01-mix.ccna.ccgslb.com.cn'


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


def handle_name_id(domain, inner_cname):
    """
    处理cname
    :param domain: 域名
    :param inner_cname: 各厂家cname
    :param other_cname: 融合统一对外cname
    :return: True or False
    """
    print('************', domain, inner_cname, '*************')

    filter_opt = {"domain": domain, "location": "default"}

    # 创建name_id 对象
    cname_db = conn_domain_cname_mongo()

    cname_obj = cname_db.find_one(filter_opt)

    if cname_obj:

        other_cname = cname_obj.get('other_cname', '')

        inner_cname_str = inner_cname

        update_doc = {
            'inner_cname': inner_cname_str
        }

        cname_db.update(filter_opt, {'$set': update_doc})

        base_msg = "default;true;%s;;;;;;120" % inner_cname_str
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

        # print('*****send dlc to 223.203.98.195')
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

        # print('*****send dlc to 223.202.202.16')
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


def check_nova_domain_icp():
    """检查融合域名icp备案"""

    # 获取需要检查的用户
    user_db = conn_user_db()
    sql = {
        'cc_icp_check': 1
    }
    user_list = user_db.find(sql)
    user_ids = []
    for user in user_list:
        user_ids.append(user.get('user_id'))

    # 获取要检查的域名
    domain_db = conn_domain_mongo()
    sql = {
        'user_id': {"$in": user_ids}
    }
    domain_doc_list = domain_db.find(sql)
    domain_list = []
    for domain_doc in domain_doc_list:
        domain_list.append(domain_doc.get('domain', ''))

    # domain_list = ['novatest06.ccindex.cn']
    print(domain_list)
    args = {
        'domain_list': domain_list,
    }

    check_result = CCAPI.check_domain_icp(args)
    print('*****icp check****', check_result)

    for domain in check_result:
        inner_cname = MIX_CNAME if check_result[domain] else RIM_CNAME
        change_reult = handle_name_id(domain, inner_cname)
        print('*******cname change********', change_reult, change_reult)

if __name__ == '__main__':
    check_nova_domain_icp()
