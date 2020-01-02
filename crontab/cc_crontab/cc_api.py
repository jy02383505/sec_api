# -*- coding: utf-8 -*-

import os
import sys
import time
import hashlib
import random
import string
import json
import urllib
import requests
from urllib import parse

sys.path.append(os.path.dirname(
    os.path.abspath(os.path.join(__file__, os.pardir))))

from api_conf import FuseApiConfig as base_config
from util import get_md5_flag

import sys
sys.getdefaultencoding()

class CCAPI(object):
    """蓝汛"""

    @staticmethod
    def get_sign_header(content_type='application/json'):
        """获取签名header"""

        key = '3b195d9b8fef756c'
        secret = '9e0750615e8281287520da8fa70afcd0'

        timestamp = str(int(time.time()))
        nonce = "".join(random.sample(string.ascii_letters + string.digits, 10))
        content_type = content_type

        str_list = [key, secret, timestamp, nonce]
        str_list_sorted = sorted(str_list)

        str_sorted = "".join(str_list_sorted).encode("utf-8")

        signature = hashlib.sha1(str_sorted).hexdigest()

        send_headers = {
            'X-CC-Auth-Key': key,
            'X-CC-Auth-Timestamp': timestamp,
            'X-CC-Auth-Nonce': nonce,
            'X-CC-Auth-Signature': signature
        }
        if content_type:
            send_headers["Content-Type"] = content_type
        return send_headers

    @staticmethod
    def domain_refresh(args):
        """域名刷新"""
        print('********domain_refresh*********')
        print(args)
        urls = args.get('urls', [])
        dirs = args.get('dirs', [])
        client_name = args.get('cms_username')

        params = dict()
        params['username'] = client_name
        params['type'] = 'm-porta'
        task_dict = {
            'urls': urls,
            'dirs': dirs
        }
        task_info = json.dumps(task_dict)
        params['task'] = task_info

        body = parse.urlencode(params).encode()

        url = 'https://r.chinacache.com/internal/refresh'

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        result = {}
        err_msg = ''

        try:
            response = requests.post(
                url, data=body, headers=headers, timeout=60)

            link_result = response.json()
            print(link_result)

            if link_result.get('code') != 0 or 'r_id' not in link_result:
                err_msg = json.dumps(link_result)
                assert False

            result['task_id'] = link_result['r_id']

        except AssertionError:
            result['err_msg'] = err_msg

        except Exception as e:
            print(e)
            result['err_msg'] = e

        return result

    @staticmethod
    def domain_refresh_status(args):
        """刷新结果"""
        print('********domain_refresh_status*********')
        print(args)
        task_id = args.get('task_id', '')
        client_name = args.get('cms_username', '')
        client_password = args.get('cms_password', '')

        refresh_conf = base_config.REFRESH_CONF['cc_contrast']

        data = {
            'username': client_name,
            'password': client_password
        }
        data_parse = urllib.parse.urlencode(data)

        url = (
            'https://r.chinacache.com/content/refresh/{}?{}'
        ).format(task_id, data_parse)

        result = {}
        err_msg = ''

        try:
            response = requests.get(url, timeout=60)

            link_result = response.json()
            print(link_result)
            refresh_result = link_result[0]

            if refresh_result['code'] != 200:
                err_msg = json.dumps(link_result)
                assert False

            status = refresh_result['status']

            result['refresh_status'] = refresh_conf[status]
            result['link_result'] = link_result

        except AssertionError:
            result['err_msg'] = err_msg

        except Exception as e:
            print(e)
            result['err_msg'] = e

        return result

    @staticmethod
    def domain_preload(args):
        """域名预热"""
        print('********domain_preload*********')
        print(args)
        urls = args.get('urls', [])
        client_name = args.get('cms_username', '')

        params = {
            'username': client_name,
            'is_repeated': True,
            "validationType": "BASIC",
        }

        task_ids = []
        tasks = []
        for url in urls:
            task_id = get_md5_flag()
            task = {"id": task_id, "url": url}
            tasks.append(task)
            task_ids.append(task_id)

        params['tasks'] = tasks

        url = 'http://r.chinacache.com/internal/preload'

        headers = {
            "Content-type": "application/json"
        }

        body = json.dumps(params).encode()

        result = {}
        err_msg = ''

        try:
            response = requests.post(
                url, data=body, headers=headers, timeout=60)

            link_result = response.json()
            print(link_result)

            if link_result.get('code') != 0 or 'r_id' not in link_result:
                err_msg = json.dumps(link_result)
                assert False

            result['task_id'] = task_ids

        except AssertionError:
            result['err_msg'] = err_msg

        except Exception as e:
            print(e)
            result['err_msg'] = e

        return result

    @staticmethod
    def domain_preload_status(args):
        """预热结果查询"""
        print('********domain_preload_status*********')
        print(args)
        task_ids = args.get('task_id', '')
        client_name = args.get('cms_username', '')
        client_password = args.get('cms_password', '')

        preload_conf = base_config.PRELOAD_CONF['cc_contrast']

        params = {
            'username': client_name,
            'password': client_password,
            "tasks": task_ids,
        }

        result = {}
        err_msg = ''
        try:
            params = json.dumps(params)
            body = params.encode()

            url = 'http://r.chinacache.com/content/preload/search'

            headers = {
                "Content-type": "application/json"
            }

            response = requests.post(
                url, data=body, headers=headers, timeout=60)

            preload_result = response.json()
            print(preload_result)

            """
            {
                'totalCount': 2,
                'tasks': [{
                    'url': 'http://www.novacdn-new-11.azure.cn/11.txt',
                    'status': 'FINISHED',
                    'percent': 100,
                    'task_id': '65555311b7cb5dbef906d74d3a48ae93'
                }, {
                    'url': 'http://www.novacdn-new-11.azure.cn/22.txt',
                    'status': 'FINISHED',
                    'percent': 100,
                    'task_id': '657d90c003d4b94150147452a56c74e4'
                }]
            }
            """
            tasks = preload_result.get('tasks', [])

            preload_status = base_config.PRELOAD_FAIL
            if len(tasks) != len(task_ids):
                result['preload_status'] = preload_status
                err_msg = json.dumps(preload_result)
                assert False

            result['link_result'] = preload_result

            status_list = []
            for task in tasks:
                status_list.append(preload_conf[task['status']])

            if base_config.PRELOAD_FAIL in status_list:
                result['preload_status'] = preload_status
                assert False

            if base_config.PRELOAD_CONDUCT in status_list:
                result['preload_status'] = base_config.PRELOAD_CONDUCT
                assert False

            result['preload_status'] = base_config.PRELOAD_SUCCESS

        except AssertionError:
            result['err_msg'] = err_msg

        except Exception as e:
            print(e)
            result['err_msg'] = e

        return result

    @staticmethod
    def check_sslcert(args):
        """检查证书"""
        client_name = args.get('cms_username', '')
        cert_name = args.get('cert_name', '')

        headers = CCAPI.get_sign_header()
        url = (
            "http://openapi.chinacache.com/cloud-ca/config/certificates?"
            "cloud_curr_client_name={}"
        ).format(client_name)

        params = {
            "cert_name": cert_name
        }

        params = json.dumps(params)
        body = params.encode()


        result = {}
        try:
            response = requests.post(
                url, data=body, headers=headers, timeout=60)
            response_json = response.json()
            if response_json['status'] == 0 and response_json['data']:
                for i in response_json['data']:
                    result = i
                    break
        except Exception as e:
            print(e)
            pass

        return result

    @staticmethod
    def update_sslcert(args):
        """更新证书"""

        # {
        #     "crt_old_id ": "5a69804b65026b22edd3f0a4",
        #     "crt_new_id ": "5979f9b74725374b43902346"
        # }
        client_name = args.get('cms_username', '')
        crt_old_id = args.get('crt_old_id', '')
        crt_new_id = args.get('crt_new_id', '')

        headers = CCAPI.get_sign_header()
        url = (
            "http://openapi.chinacache.com/cloud-ca/certification/update?"
            "cloud_curr_client_name={}"
        ).format(client_name)

        params = {
            "crt_old_id": crt_old_id,
            "crt_new_id": crt_new_id
        }

        params = json.dumps(params)
        body = params.encode()

        result = False
        try:
            response = requests.post(
                url, data=body, headers=headers, timeout=60)
            response_json = response.json()
            if response_json['status'] == 0:
                result = True

        except Exception as e:
            print(e)
            pass

        return result

    @staticmethod
    def check_domain_icp(args):
        """检查域名icp备案情况"""
        domain_list = args.get('domain_list', [])

        check_result_dict = {}

        for domain in domain_list:
            # url = (
            #     "http://223.202.214.75:8089/business.php?"
            #     "Rstrcommand=ICP.Query&Rstrusername=sysadmin"
            #     "&RstrePassword=Xxj3NUKfrRzV&queryType=0&queryCondition={}"
            # ).format(domain)

            url = 'http://223.202.214.75:8089/?module=icpquery&domain={}'.format(domain)

            print('url:', url)
            response = requests.get(url, timeout=60)
            response.encoding = response.apparent_encoding
            result = response.text
            """
            status=1&value=京ICP证020384号-4&Wzmc=WEBLUKER&Ztbah=京ICP证020384号&Ztmc=北京蓝汛通信技术有限责任公司&uptime=1569381704
            status=0&value=&Wzmc=&Ztbah=&Ztmc=&uptime=1569381704
            """
            # result = 'status=1&value=京ICP证020384号-4&Wzmc=WEBLUKER&Ztbah=京ICP证020384号&Ztmc=北京蓝汛通信技术有限责任公司&uptime=1569381704'

            result = parse.parse_qs(result)
            print(result)

            status = result.get('status', [])
            check_result = True if '1' in status else False

            check_result_dict[domain] = check_result


        return check_result_dict

    @staticmethod
    async def check_status(args):
        import datetime
        import aiohttp
        from aiohttp import TCPConnector
        domain_list = args.get('domain_list', [])
        start_time = 1571136600
        end_time = 1571223000

        client_name = 'ccemea'

        for channel in domain_list:
            headers = CCAPI.get_sign_header()

            code_url = (
                'http://openapi.chinacache.com/imp/api/v1.0/status_code/'
                'open/count?channel_name={}&start_time={}&end_time={}'
                '&cloud_curr_client_name={}'
            ).format(channel, start_time, end_time, client_name)

            print(code_url)
            print(headers)
            print(datetime.datetime.now())
            # response = requests.get(code_url, headers=headers, timeout=60)
            # response_json = response.json()

            timeout_obj = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(
                    timeout=timeout_obj, headers=headers,
                    connector=TCPConnector(verify_ssl=False)) as session:
                async with session.get(code_url) as response:
                    response_json = await response.json()

            print(response_json)
            print(datetime.datetime.now())


if __name__ == '__main__':
    import asyncio
    the_args = {
        'domain_list': [
            'https://wahaha.com',
            'http://wahaha.com',
            'http://novatest03.ccindex.cn',
            'http://novatest04.ccindexnoicp.cn',
            'http://novatest05.ccindexnoicp.cn',
            'http://novatest06.ccindex.cn',
            'https://novatest06.ccindex.cn',

        ],
        # 'domain_list': ['www.baidu.com'],
    }
    # res = CCAPI.check_status(the_args)


    loop = asyncio.get_event_loop()
    loop.run_until_complete(CCAPI.check_status(the_args))
