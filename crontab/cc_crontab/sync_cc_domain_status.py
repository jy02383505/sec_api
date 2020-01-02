"""
CC 域名同步状态
"""
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


MODIFY_TIME_LIMIT = 60 * 40    # 修改或添加的极限时间
ADD_RATIO = 100    # 添加域名比例
EDIT_RATIO = 95    # 添加域名比例
DIG_CACHE_TIME = 60 * 3    # cname缓存时间
DIG_CACHE_TIMEOUT = 60 * 20    # cname隐藏超时时间
ALL_DNS_SUCC = 60 * 2    # 所有dns成功时间


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


class SyncDomainStatus(object):
    """同步域名状态
    task_db
        status
            1 添加配置中
            2 加速中
            3 修改配置中
            4 报停
            5 cname 隐藏时间
            6 dns生效
            -1 异常
    """
    CREATING = 1
    SERVING = 2
    EDITING = 3
    STOPPING = 4
    DIS_CNAME = 5
    DNS_TASK_EFFECT = 6
    ACTIVATING = 7
    ERROR = -1

    def __init__(self):
        self.domain_db = conn_domain_mongo()
        self.task_db = conn_cc_domain_task_mongo()
        self.cname_db = conn_domain_cname_mongo()
        self.opt_domain_list = []

    def set_task_doc(self, channel, update_doc):
        """修改任务表数据"""
        search_filer = {
            'channel': channel
        }

        self.task_db.update(search_filer, {'$set': update_doc})

    @classmethod
    def get_domain_cname(cls, channel):
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
        cname = res.get('ROOT', {}).get(
            'BODY', {}).get('OUT_DATA', {}).get('cname', '')

        return cname

    @classmethod
    def check_task_progress(cls, accept_num, task_type='is_create'):
        """
        检查任务进度
        :param accept_num: 流水号
        :param task_type: is_create is_edit
        :return: 0 进行中, 1 完成, -1 错误
        """
        url = 'https://cms3-apir.chinacache.com/tm-api/task/taskResult'

        params = {
            "ROOT": {
                "HEADER": {},
                "BODY": {
                    "BUSI_INFO": {
                        "operAccept": int(accept_num)
                    }
                }
            }
        }
        headers = {
            "Content-type": "application/json"
        }
        params = json.dumps(params)
        print(params)
        body = params.encode()
        response = link(url, 'POST', headers, body=body)
        check_result = -1

        if response != -1:
            check_result = response.json()
            print(check_result)

            """
            {
                'ROOT': {
                    'HEADER': {},
                    'BODY': {
                        'OUT_DATA': {
                            'operAccept': 9531047,
                            'taskStatus': '下发中',
                            'succCount': 0,
                            'totalCount': 0
                        },
                        'RETURN_CODE': '0',
                        'RETURN_MSG': 'OK'
                    }
                }
            }
            """

            out_data = check_result.get(
                'ROOT', {}).get('BODY', {}).get('OUT_DATA', {})
            success_count = out_data.get('succCount', 0)
            total_count = out_data.get('totalCount', 0)
            # task_status = out_data.get('taskStatus', '')

            check_result = 0

            if total_count == 0:
                check_result = -1
            else:
                cur_ratio = float(success_count) / float(total_count) * 100

                if task_type == 'is_create' and cur_ratio >= ADD_RATIO:
                    check_result = 1
                elif task_type == 'is_edit' and cur_ratio >= EDIT_RATIO:
                    check_result = 1

                # if task_type == 'is_create':
                #     if task_status == '完成' and success_count != total_count:
                #         check_result = -1
                #
                #     elif cur_ratio >= ADD_RATIO:
                #         check_result = 1
                # elif task_type == 'is_edit':
                #
                #     if cur_ratio >= EDIT_RATIO:
                #         check_result = 1

        return check_result, cur_ratio

    def handle_name_id(self, domain, inner_cname, other_cname):
        """
        处理cname
        :param domain: 域名
        :param inner_cname: 各厂家cname
        :param other_cname: 融合统一对外cname
        :return: True or False
        """

        filter_opt = {"domain": domain, "location": "default"}

        # 创建name_id 对象
        cname_obj = self.cname_db.find_one(filter_opt)

        if not cname_obj:
            inner_cname_str = ",".join([inner_cname])

            data = {
                "domain": domain,
                "inner_cname": inner_cname_str,
                "other_cname": other_cname,
                "location": "default",
                "add_time": datetime.datetime.now(),
            }
            self.cname_db.insert(data)

        else:
            inner_cname = cname_obj.get('inner_cname', [])
            inner_cname_list = inner_cname.split(',')
            inner_cname_list.append(inner_cname)

            inner_cname_str = ",".join(inner_cname_list)

            update_doc = {
                'inner_cname': inner_cname_str
            }

            self.cname_db.update(filter_opt, {'$set': update_doc})

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

    def handle_add_domain(self, task):
        """处理添加"""
        task_id = task.get('task_id', 0)
        channel = task.get('channel', 0)
        other_cname = task.get('cname', '')
        domain = task.get('domain', '')
        dis_cname = task.get('dis_cname', False)

        check_result, cur_ratio = self.check_task_progress(task_id)

        if check_result == -1:
            doc = {
                'status': SyncDomainStatus.ERROR,
                'err_msg': 'add task progress error'
            }
            self.set_task_doc(channel, doc)

        elif check_result == 1:
            inner_cname = self.get_domain_cname(channel)
            self.handle_name_id(domain, inner_cname, other_cname)

            if not dis_cname:
                doc = {
                    'status': SyncDomainStatus.SERVING,
                    'err_msg': '',
                    'task_id': '',
                    'modify_time': '',
                    'task_progress': cur_ratio,
                }
                self.set_task_doc(channel, doc)
            else:
                doc = {
                    'status': SyncDomainStatus.DIS_CNAME,
                    'err_msg': '',
                    'modify_time': datetime.datetime.now(),
                    'task_progress': cur_ratio,
                }
                self.set_task_doc(channel, doc)
        else:
            doc = {
                'task_progress': cur_ratio,
            }
            self.set_task_doc(channel, doc)

    def handle_edit_domain(self, task):
        """处理添加"""
        task_id = task.get('task_id', 0)
        channel = task.get('channel', 0)

        check_result, cur_ratio = self.check_task_progress(
            task_id, task_type='is_edit')

        if check_result == -1:
            doc = {
                'status': SyncDomainStatus.ERROR,
                'err_msg': 'add task progress error'
            }
            self.set_task_doc(channel, doc)

        elif check_result == 1:
                doc = {
                    'status': SyncDomainStatus.SERVING,
                    'err_msg': '',
                    'task_id': '',
                    'modify_time': '',
                    'task_progress': cur_ratio,
                }
                self.set_task_doc(channel, doc)
        else:
            doc = {
                'task_progress': cur_ratio,
            }
            self.set_task_doc(channel, doc)

    def handle_active_domain(self, task):
        """处理激活"""
        task_id = task.get('task_id', 0)
        channel = task.get('channel', 0)
        other_cname = task.get('cname', '')
        domain = task.get('domain', '')
        dis_cname = task.get('dis_cname', False)

        check_result, cur_ratio = self.check_task_progress(task_id)

        if check_result == -1:
            doc = {
                'status': SyncDomainStatus.ERROR,
                'err_msg': 'add task progress error'
            }
            self.set_task_doc(channel, doc)

        elif check_result == 1:
            inner_cname = self.get_domain_cname(channel)
            self.handle_name_id(domain, inner_cname, other_cname)

            if not dis_cname:
                doc = {
                    'status': SyncDomainStatus.SERVING,
                    'err_msg': '',
                    'task_id': '',
                    'modify_time': '',
                    'task_progress': cur_ratio,
                }
                self.set_task_doc(channel, doc)
            else:
                doc = {
                    'status': SyncDomainStatus.DIS_CNAME,
                    'err_msg': '',
                    'modify_time': datetime.datetime.now(),
                    'task_progress': cur_ratio,
                }
                self.set_task_doc(channel, doc)
        else:
            doc = {
                'task_progress': cur_ratio,
            }
            self.set_task_doc(channel, doc)

    def check_dis_cname(self, task):
        """检查隐藏cname"""

        status = task.get('status')
        cname = task.get('cname', '')
        channel = task.get('channel', '')
        modify_time = task.get('modify_time', '')

        modify_time = datetime_to_timestamp(modify_time)
        sub_time = time.time() - modify_time

        if status == SyncDomainStatus.DIS_CNAME:

            if sub_time > DIG_CACHE_TIME:

                dig_test_str = 'dig %s |grep "CNAME" |wc -l' % cname
                print(dig_test_str)
                output = os.popen(dig_test_str)
                check_dig_result = output.read()

                check_dig_result = check_dig_result.strip()

            if sub_time > DIG_CACHE_TIMEOUT and int(check_dig_result) != 0:

                doc = {
                    'status': SyncDomainStatus.ERROR,
                    'err_msg': 'cname diss error'
                }
                self.set_task_doc(channel, doc)

            elif check_dig_result == '0':

                doc = {
                    'status': SyncDomainStatus.DNS_TASK_EFFECT,
                    "modify_time": datetime.datetime.now()
                }
                self.set_task_doc(channel, doc)

        elif status == SyncDomainStatus.DNS_TASK_EFFECT:

            if sub_time > ALL_DNS_SUCC:

                doc = {
                    'status': SyncDomainStatus.SERVING,
                    'err_msg': '',
                    'task_id': '',
                    'modify_time': ''
                }
                self.set_task_doc(channel, doc)

    def get_opt_domain(self):
        """获取需要操作域名"""
        filter_opt = {
            "status": {'$in': [SyncDomainStatus.CREATING,
                               SyncDomainStatus.EDITING,
                               SyncDomainStatus.ACTIVATING]}
        }

        task_list = self.task_db.find(filter_opt)

        now_timestamp = datetime_to_timestamp(datetime.datetime.now())

        for task in task_list:

            channel = task.get('channel', '')
            domain = task.get('domain', '')
            task_id = task.get('task_id', '')
            status = task.get('status', '')
            cname = task.get('cname', '')
            modify_time = task.get('modify_time', '')
            dis_cname = task.get('dis_cname', False)

            # 超时检查
            if modify_time:
                modify_time = datetime_to_timestamp(modify_time)
                if now_timestamp - modify_time > MODIFY_TIME_LIMIT:
                    doc = {
                        'status': SyncDomainStatus.ERROR,
                        'err_msg': 'is timeout'
                    }
                    self.set_task_doc(channel, doc)
                    continue

            task_info = {
                'channel': channel,
                'domain': domain,
                'task_id': task_id,
                'status': status,
                'cname': cname,
                'modify_time': modify_time,
                'dis_cname': dis_cname
            }

            self.opt_domain_list.append(task_info)

    def handle_accept(self):
        """处理流水任务"""
        print(self.opt_domain_list)
        for i in self.opt_domain_list:
            try:
                status = i.get('status', '')

                if status == SyncDomainStatus.CREATING:
                    self.handle_add_domain(i)

                elif status == SyncDomainStatus.EDITING:
                    self.handle_edit_domain(i)

                elif status in [SyncDomainStatus.DIS_CNAME,
                                SyncDomainStatus.DNS_TASK_EFFECT]:
                    self.check_dis_cname(i)

                elif status == SyncDomainStatus.ACTIVATING:
                    self.handle_active_domain(i)
            except Exception as e:
                print('get status error')
                print(i)
                print(e)

    def __call__(self):
        self.get_opt_domain()
        self.handle_accept()


if __name__ == '__main__':
    s = SyncDomainStatus()
    s()


