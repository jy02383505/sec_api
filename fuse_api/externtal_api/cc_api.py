

import json
import copy
import time
import random
import string
import hashlib
import datetime

from lib.api_conf import FuseApiConfig
from lib.util import web_link, timestamp_to_str, get_time_list, datetime_to_str

import ssl

class CCAPI(object):

    def __init__(self, domain):
        self.domain = domain

    @staticmethod
    async def test(args):
        print('cc test', args)

        return 1, 'success'

    @staticmethod
    async def get_opt_channel(domain, mongodb):
        """获取预处理频道"""
        cc_task_db = mongodb.CC_CDN_domain_info
        search_sql = {
            'domain': domain
        }

        result = []
        async for doc in cc_task_db.find(search_sql):
            doc.pop('_id')
            result.append(doc)

        return result

    @staticmethod
    async def get_opt_channels(domains, mongodb):
        """获取预处理频道"""
        cc_task_db = mongodb.CC_CDN_domain_info
        search_sql = {
            'domain': {'$in': domains}
        }

        result = []
        async for doc in cc_task_db.find(search_sql):
            doc.pop('_id')
            result.append(doc)

        return result

    @staticmethod
    async def get_channel_task(domain, protocol, mongodb):
        """获取预处理频道"""
        cc_task_db = mongodb.CC_CDN_domain_info
        search_sql = {
            'channel': '%s://%s' % (protocol, domain)
        }
        result = await cc_task_db.find_one(search_sql)
        return result

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
    async def create_sf_domain(args):
        """在sf创建域名 返回channel_id"""
        print('*********sf create domain*********')
        channel = args.get('channel', '')
        need_to_log = args.get('NeedToLog', True)
        pub_is_filter = args.get('pubIsFilter', False)
        log_format = args.get('LogFormat', 'w3c')

        contractno = args.get('contract_name', '')
        account_id = args.get('cms_username', '')
        productno = args.get('productno', '')

        # 正式环境
        url = ('https://chinacache1.secure.force.com/'
               'services/apexrest/FusioncChannelToCRM')

        # # 测试环境
        # url = ('https://dev-chinacache1.cs75.force.com/'
        #        'services/apexrest/FusioncChannelToCRM')

        headers = {
            'cookies': 'debug_logs=debug_logs;domain=.force.com',
            "content-type": "application/json",
        }

        body_list = []
        body = {
            "Name": channel,
            "AccountID": account_id,
            "productno": productno,
            "contractno": contractno,
            "NeedToLog": need_to_log,
            "pubIsFilter": pub_is_filter,
            "LogFormat": log_format,
        }

        body_list.append(body)

        params = body_list

        print('url:', url)
        print('body:', body_list)

        err_msg = ''
        channel_id = ''

        try:
            code, res = await web_link(url, headers=headers, body=params)
            # print(code, res)

            """
            {
                "status": "success",
                "message": "",
                "channels2": {
                    "http://itestxz0005.chinacache.com": "156512"
                },
                "channels": ["156512"]
            }
            """
            if not code:
                err_msg = res
                assert False

            if res.get('status', '') != "success":
                err_msg = res.get('message', '')
                assert False

            channel_id = res.get('channels', [])[0]
        except AssertionError:
            pass

        except Exception as e:
            err_msg = e

        return err_msg, channel_id

    @staticmethod
    async def operation_cms_domain(args, opt):
        """操作域名"""
        print('*********cms operation domain*********')
        channel = args.get('channel', "")
        crt_name = args.get('crt_name', "")
        service_id = args.get('service_id', "")

        # 回源配置
        src_type = args.get('src_type', '')
        if src_type == 'ip':
            back_type = 'IPCOMMONCONFIG'
        elif src_type == 'dmn':
            back_type = 'ORIGDOMAIN'

        back_domain = args.get('src_domain', "")
        back_ips = args.get('src_ips', [])

        # 备回源配置
        src_back_type = args.get('src_back_type', '')
        back_backup_type = ''
        if src_back_type == 'ip':
            back_backup_type = 'IP'
        elif src_back_type == 'dmn':
            back_backup_type = 'DMN'

        back_backup_ips = args.get('src_back_ips', [])
        back_backup_domain = args.get('src_back_domain', '')

        # 回源host
        back_host = args.get('src_host', '')
        # 是否忽略cache_control 1 or 0
        ignore_cache_control = args.get('ignore_cache_control', '')
        # 是否忽略?后面参数 1 or 0
        ignore_query_string = args.get('ignore_query_string', '')

        # 缓存策略
        cache_rule = args.get('cache_rule', [])

        cc_rule_list = []
        for i in cache_rule:
            cache_type = i.get('type', '')

            if cache_type == 'suffix':
                cc_value = i.get('rule', '').replace(';', '|').replace('.', '')
                cc_type = 'EXTENSION'
            elif cache_type in 'path':
                cc_value = i.get('rule', '').replace(';', ' ')
                cc_type = 'PATHMATCH'

            ttl = i.get('ttl', 0)
            ttl = int(ttl)
            no_cache = '1' if ttl <= 0 else '0'

            temp_rule = {
                "input_public_matchCont": cc_value,
                "input_public_matchType": cc_type,
                "input_public_timeSecond": str(ttl),
                "input_public_nocachFlag": no_cache,
                "input_public_timeType": "1"
            }
            cc_rule_list.append(temp_rule)

        params = {
            "ROOT": {
                "BODY": {
                    "BUSI_INFO": {
                        'BUSI_CONF_INFO': {
                            "FUNC_CONF_INFO": {
                                "CN002600": ignore_cache_control,
                                "CN002650": ignore_query_string,
                                "CN002100": cc_rule_list,
                            }
                        },
                        "CHN_NAME": channel,
                        "CRT_NAME": crt_name,
                        "OP_TYPE": opt,
                        "SELFSRV_ID": service_id,

                        "SOURCE_CONF_INFO": {
                            "BACKSTRGS": [
                                {
                                    # 备份回源
                                    "backupType": back_backup_type,
                                    "backupDmn": back_backup_domain,
                                    "backBackupIps": back_backup_ips,
                                    # 回源
                                    "backIps": back_ips,
                                    "backDmns": back_domain,
                                    "backStrg": "Common",

                                }
                            ],
                            "BACK_TYPE": back_type,
                            "BACK_HOST": back_host,
                        },
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

        # url = 'http://223.202.75.26:32000/bm-app/apiw/9040/addChannel'
        url = 'http://cms3-apiw.chinacache.com/apiw/9040/addChannel'

        print(url)
        print(2222222222, params)
        task_id = ''
        err_msg = ''

        try:
            code, res = await web_link(url, headers=headers, body=params)
            print(code, res)
            """
            {
                'ROOT': {
                    'HEADER': {},
                    'BODY': {
                        'OUT_DATA': {
                            'OPER_ACCEPT': 9530574
                        },
                        'RETURN_CODE': '0',
                        'RETURN_MSG': 'OK'
                    }
                }
            }
            """
            if not code:
                err_msg = res
                assert False
            res_body = res.get('ROOT', {}).get('BODY', {})

            if res_body.get('RETURN_CODE', '0') == '0':
                task_id = res_body.get('OUT_DATA', {}).get('OPER_ACCEPT', '')
            else:
                err_msg = res_body.get('RETURN_MSG', '')

        except AssertionError:
            pass

        except Exception as e:
            err_msg = e

        return err_msg, task_id

    @staticmethod
    async def create_domain(args):
        """cc 创建域名"""
        print('*********create_domain**********')
        print(args)
        mongodb = args.get('mongodb')

        task_db = mongodb.CC_CDN_domain_info

        user_doc = args.get('user_doc', {})

        cc_cms_template_type = user_doc.get('cc_cms_template_type', 2)
        cms_username = user_doc.get('cms_username', '')
        base_cname = user_doc.get('base_cname', '')
        dis_cname = user_doc.get('dis_cname', False)
        contract_info = user_doc.get('contract', {})

        protocol_list = args.get('protocol', [])
        base_template_id = args.get('base_template_id', '')
        cdn_type = args.get('cdn_type', '')
        crt_name = args.get('crt_name', '')

        domain = args.get('domain', '')
        cname = '%s%s' % (domain, base_cname)

        contract_name = args.get('contract_name', '')
        contract = contract_info.get(contract_name, {})

        for protocol in protocol_list:


            channel = '{}://{}'.format(protocol, domain)

            service_id = ''

            for p in contract.get('product', []):
                check_name = p['product_name'].lower()

                if '融合' in check_name:
                    service_id = base_template_id
                    product_code = p['product_code']
                else:
                    if cdn_type in check_name:

                        if protocol == 'https' and protocol in check_name:
                            service_id = base_template_id \
                                if cc_cms_template_type == 2 \
                                else p.get('service_id', '')
                            product_code = p['product_code']
                            break

                        elif protocol == 'http':
                            service_id = base_template_id if \
                                cc_cms_template_type == 2 \
                                else p.get('service_id', '')
                            product_code = p['product_code']
                            break
            print('*************', service_id)
            if not service_id:
                continue

            args_update = {
                'cms_username': cms_username,
                'channel': channel,
                'service_id': service_id,
                'productno': product_code,
                'cname': cname,
                'dis_cname': dis_cname,
            }

            if protocol == 'http':
                args['crt_name'] = ''
            elif protocol == 'https':
                args['crt_name'] = crt_name
            args.update(args_update)

            print(channel)
            print(args)

            flag = False
            err_msg = ''
            result = {}
            try:
                err_msg, channel_id = await CCAPI.create_sf_domain(args)
                if err_msg:
                    assert False

                err_msg, task_id = await CCAPI.operation_cms_domain(args, "I")
                if err_msg:
                    assert False

                result['task_id'] = task_id
                result['channel_id'] = channel_id

                task_search_sql = {
                    'channel': channel,
                }

                task_doc = {
                    'domain': domain,
                    'channel': channel,
                    'status': 1,
                    'cdn_type': cdn_type,
                    'cname': cname,
                    'dis_cname': dis_cname,
                    'task_id': task_id,
                    'service_id': str(service_id),
                    'channel_id': channel_id,
                    'modify_time': datetime.datetime.now()
                }

                old_doc = await task_db.find_one(task_search_sql)
                if not old_doc:
                    await task_db.insert_one(task_doc)
                else:
                    await task_db.update_many(
                        task_search_sql, {"$set": task_doc})

                flag = True

            except AssertionError:
                result = err_msg

            except Exception as e:
                result = e

        return flag, result

    @staticmethod
    async def edit_domain(args):
        """cc 修改域名"""
        print('*********edit_domain**********')
        flag = False
        err_msg = ''
        result = {}

        mongodb = args.get('mongodb')
        domain = args.get('domain', '')

        crt_name = args.get('crt_name', '')

        cc_task_db = mongodb.CC_CDN_domain_info

        channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)

        try:
            for channel_doc in channel_doc_list:
                channel = channel_doc.get('channel', '')
                print('----------------', channel)
                service_id = channel_doc.get('service_id', '')

                args['channel'] = channel
                args['service_id'] = service_id

                if 'https' in channel:
                    args['crt_name'] = crt_name
                else:
                    args['crt_name'] = ''


                err_msg, task_id = await CCAPI.operation_cms_domain(args, "U")
                if err_msg:
                    assert False

                search_sql = {
                    'channel': channel
                }

                update_doc = {
                    'task_id': task_id,
                    'modify_time': datetime.datetime.now(),
                    'task_progress': 0,
                    'status': 3
                }

                cc_task_db.update_one(search_sql, {'$set': update_doc})


            flag = True

        except AssertionError:
            result = err_msg

        except Exception as e:
            result = e

        return flag, result

    @staticmethod
    async def sync_domain_conf(args):
        """查询域名配置"""

        domain = args.get('domain', '')
        protocol = args.get('protocol', '')

        mongodb = args.get('mongodb')

        channel_doc = await CCAPI.get_channel_task(domain, protocol, mongodb)

        channel_id = channel_doc.get('channel_id')

        flag = False
        err_msg = ''
        try:
            params = {
                "ROOT": {
                    "BODY": {
                        "BUSI_INFO": {
                            "CHN_ID": channel_id,
                             "CODE": "CN001300"
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

            url = 'http://cms3-apir.chinacache.com/apir/9040/qryChnConf'

            print(url)
            print(params)
            err_msg = ''

            code, res = await web_link(url, headers=headers, body=params)

            print(res)

            res_body = res.get('ROOT', {}).get('BODY', {})
            if res_body.get('RETURN_CODE', '') != '0':
                err_msg = res_body.get('RETURN_MSG', '')
                assert False

            out_data = res_body.get('OUT_DATA', {})

            # 回源信息
            src_conf = out_data.get('SOURCE_CONF', [])[0]

            back_type = src_conf.get('backType', 'IPCOMMONCONFIG')

            src_type = ''
            if back_type == 'IPCOMMONCONFIG':
                src_type = 'ip'
            elif back_type == 'ORIGDOMAIN':
                src_type = 'dmn'

            back_ips = src_conf.get('backIps', [])
            back_domain = src_conf.get('backDmns', '')

            back_backup_type = src_conf.get('backupType', '')
            src_back_type = ''
            if back_backup_type == 'IP':
                src_back_type = 'ip'
            elif back_backup_type == 'DMN':
                src_back_type = 'dmn'
            back_backup_ips = src_conf.get('backBackupIps', [])
            back_backup_domain = src_conf.get('backupDmn', '')

            func_conf = out_data.get('FUNC_CONF_INFO', {})

            # 回源host
            back_host = ''
            back_hosts = func_conf.get('CN008400', [])
            if back_hosts:
                back_host = back_hosts[0].get(
                    'params', {}).get('input_public_hostHeader', '')

            ignore_query_string = 1 if func_conf.get('CN002650', []) else 0
            ignore_cache_control = 1 if func_conf.get('CN002600', []) else 0

            cc_rule_list = func_conf.get('CN002100', [])

            cache_rule = []
            for i in cc_rule_list:
                params = i.get('params', {})

                cc_type = params.get('input_public_matchType', '')
                cc_rule = params.get('input_public_matchCont', '')
                cc_time = params.get('input_public_timeSecond', '')

                if cc_type == 'PATHMATCH':
                    rule = cc_rule.replace(' ', ';')
                    cache_type = 'path'
                elif cc_type == 'EXTENSION':
                    rule = cc_rule.replace('|', ';')
                    cache_type = 'suffix'

                cache_info = {
                    'rule': rule,
                    'type': cache_type,
                    'ttl': cc_time,
                }

                cache_rule.append(cache_info)

            # 证书信息
            cc_cert_id = out_data.get('CERTIFICATE_INFO', {}).get('extnId', '')

            cert_info = {}
            if cc_cert_id:
                cert_db = mongodb.cert
                search_sql = {
                    'send_info.CC.cert_id': cc_cert_id
                }
                cert_doc = await cert_db.find_one(search_sql)

                cert_name = cert_doc.get('cert_name', '')
                cert_from = cert_doc.get('cert_from', 0)
                end_time = cert_doc.get('end_time', 0)
                end_time = datetime_to_str(end_time)
                status = cert_doc.get('status')
                remark = cert_doc.get('remark', '')

                cert_info = {
                    'cert_name': cert_name,
                    'cert_from': cert_from,
                    'end_time': end_time,
                    'status': status,
                    'remark': remark
                }

            result = {
                'src_type': src_type,
                'src_domain': back_domain,
                'src_ips': back_ips,

                'src_back_type': src_back_type,
                'src_back_ips': back_backup_ips,
                'src_back_domain': back_backup_domain,

                'src_host': back_host,

                'ignore_query_string': ignore_query_string,
                'ignore_cache_control': ignore_cache_control,

                'cache_rule': cache_rule,

                'cdn_type': channel_doc.get('cdn_type', ''),
                'cname': channel_doc.get('cname', ''),
                'status': channel_doc.get('status', ''),

                'cert_info': cert_info
            }

            flag = True

        except AssertionError:
            result = err_msg

        except Exception as e:
            result = e

        return flag, result

    @staticmethod
    async def domain_flux(args):
        """
        计费数据
        :param args:
        :return: 返回流量单位(MB)
        """
        def def_handle_api_data(api_data, source_data):
            """处理api返回数据"""
            api_data_dict = {}
            for flux_data in api_data:
                _key = datetime.datetime.strptime(
                    flux_data, '%Y%m%d%H%M').strftime("%Y-%m-%d %H:%M")
                api_data_dict[_key] = [
                    round((api_data[flux_data]*300/8/1000)/1000,6),
                    round((source_data[flux_data]*300/8/1000)/1000,6)
                ]
            return api_data_dict

        domain = args.get('domain', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')
        remove_upper_layer = user_doc.get('remove_upper_layer')

        channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)

        # 全部时间节点
        time_list = get_time_list(start_time, end_time)

        # 时间格式转化
        time_format = '%Y%m%d'
        start_time = timestamp_to_str(start_time, _format=time_format)
        end_time = timestamp_to_str(end_time, _format=time_format)

        result = {}

        for time_key in time_list:
            result.setdefault(time_key, [0, 0])

        status = False
        try:
            for channel_doc in channel_doc_list:

                channel_id = channel_doc.get('channel_id')

                headers = CCAPI.get_sign_header()
                cdn_url = (
                    'http://openapi.chinacache.com/cloud-bill/bandwidth?'
                    'start_time={}&end_time={}&channel_id={}&'
                    'show_time=true&cloud_curr_client_name={}'
                ).format(start_time, end_time, channel_id, client_name)

                if remove_upper_layer:
                    cdn_url += '&layer_type=EDGE'

                start = time.time()
                _, cdn_result = await web_link(
                    cdn_url, headers=headers, method='GET')
                # print(cdn_url)
                # print('******************cdn_flux_time', time.time()-start)
                # print(cdn_result)

                headers = CCAPI.get_sign_header()
                src_url = (
                    'http://openapi.chinacache.com/cloud-bill/bandwidth/'
                    'source?start_time={}&end_time={}&channel_id={}'
                    '&show_time=true&cloud_curr_client_name={}'
                ).format(start_time, end_time, channel_id, client_name)

                start = time.time()
                _, src_result = await web_link(src_url, headers, method='GET')
                # print(src_url)
                # print('******************src_flux_time', time.time() - start)

                channel_result = def_handle_api_data(
                    cdn_result['data'][0]['detail_data'][0]['bandwidths'],
                    src_result['data'][0]['detail_data'][0]['bandwidths']
                )

                for key in result:
                    if key in channel_result:
                        result[key][0] += channel_result[key][0]
                        result[key][1] += channel_result[key][1]
                status = True
        except Exception as e:
            print(e)

        return status, result

    # @staticmethod
    # async def domain_request(args):
    #     """
    #     请求量数据
    #     :param args:
    #     :return:
    #     """
    #
    #     domain = args.get('domain', '')
    #     start_time = args.get('start_time')
    #     end_time = args.get('end_time')
    #
    #     # 全部时间节点
    #     time_list = get_time_list(start_time, end_time)
    #
    #     user_doc = args.get('user_doc')
    #     mongodb = args.get('mongodb')
    #
    #     client_name = user_doc.get('cms_username')
    #
    #     channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)
    #
    #     # 通信api时间格式转换
    #     time_format = '%Y%m%d'
    #     end_time += 300
    #     end_time_str = timestamp_to_str(end_time, _format=time_format)
    #     start_time_str = timestamp_to_str(start_time, _format=time_format)
    #
    #     result = {}
    #
    #
    #     status = False
    #
    #     try:
    #         for channel_doc in channel_doc_list:
    #             channel_id = channel_doc.get('channel_id')
    #
    #             headers = CCAPI.get_sign_header()
    #
    #             request_url = (
    #                 "https://openapi.chinacache.com/data/statistics/channel/"
    #                 "status_hit?cloud_curr_client_name={}&channel_id={}"
    #                 "&start_time={}&end_time={}&time_type=five_m"
    #             ).format(client_name, channel_id, start_time_str, end_time_str)
    #
    #             _, request_result = await web_link(
    #                 request_url, headers=headers, method='GET')
    #
    #             data = request_result.get('data', [])
    #
    #             for i in data:
    #                 time_key = datetime.datetime.strptime(
    #                     i["time"], '%Y%m%d%H%M').strftime("%Y-%m-%d %H:%M")
    #
    #                 if time_key in time_list:
    #                     result.setdefault(
    #                         time_key, {'requests': 0, 'hit': 0, 'miss': 0})
    #
    #                     hit_count = 0
    #                     miss_count = 0
    #
    #                     for j in i["detail_data"]:
    #
    #                         if j['status_hit'] == 'MISS':
    #                             miss_count += j['detail_data']['request']
    #
    #                         if j['status_hit'] == 'HIT':
    #                             hit_count += j['detail_data']['request']
    #
    #                     request_count = hit_count + miss_count
    #
    #                     result[time_key]['requests'] += request_count
    #                     result[time_key]['hit'] += hit_count
    #                     result[time_key]['miss'] += miss_count
    #
    #         status = True
    #     except Exception as e:
    #         print(e)
    #
    #     return status, result


    @staticmethod
    async def domain_request(args):
        """
        请求量数据
        :param args:
        :return:
        """

        domain = args.get('domain', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')

        channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)

        end_time += 300
        # 通信api时间格式转换
        time_format = '%Y%m%d%H%M'
        end_time_str = timestamp_to_str(end_time, _format=time_format)
        start_time_str = timestamp_to_str(start_time, _format=time_format)

        result = {}

        status = False

        try:
            for channel_doc in channel_doc_list:
                channel_id = channel_doc.get('channel_id')

                headers = CCAPI.get_sign_header()

                request_url = (
                    'http://openapi.chinacache.com/cloud-data/statistics/'
                    'channel?start_time={}&end_time={}&channel_id={}'
                    '&time_type=MINUTE5&cloud_curr_client_name={}'
                ).format(start_time_str, end_time_str, channel_id, client_name)

                start = time.time()
                _, request_result = await web_link(
                    request_url, headers=headers, method='GET')
                print(request_url)
                print('******************request_time', time.time()-start)

                for data in request_result['data']:
                    time_key = datetime.datetime.strptime(
                        data["time"], '%Y%m%d%H%M%S').strftime("%Y-%m-%d %H:%M")

                    result.setdefault(
                        time_key, {'requests': 0, 'hit': 0, 'miss': 0})

                    temp_data = data["detail_data"]["request"]

                    result[time_key]['requests'] += temp_data["total"]
                    result[time_key]['hit'] += temp_data["hit"]
                    result[time_key]['miss'] += temp_data["mis"]

            status = True
        except Exception as e:
            print(e)

        return status, result

    @staticmethod
    async def domain_status_code(args):
        """
        状态码数据
        :param args:
        :return:
        """
        base_trend = ['2xx', '3xx', '4xx', '5xx']

        sc_config = FuseApiConfig.STATUS_CODES
        other = FuseApiConfig.OTHER

        domain = args.get('domain', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        app_loop = args.get('app_loop', None)

        client_name = user_doc.get('cms_username')

        channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)

        result = {}

        code_result = {}
        trend_result = {}

        # 全部时间节点
        time_list = get_time_list(start_time, end_time)

        for time_key in time_list:
            code_result.setdefault(
                time_key, copy.deepcopy(sc_config['base_code']))

            trend_result.setdefault(time_key, {})
            for c in base_trend:
                trend_result[time_key][c] = 0

        status = False

        try:
            for channel_doc in channel_doc_list:
                channel = channel_doc.get('channel')

                headers = CCAPI.get_sign_header()

                code_url = (
                    'http://openapi.chinacache.com/imp/api/v1.0/status_code/'
                    'open/count?channel_name={}&start_time={}&end_time={}'
                    '&cloud_curr_client_name={}'
                ).format(channel, start_time, end_time, client_name)



                start = time.time()
                print('code_url', code_url, start)
                _, api_result = await web_link(
                    code_url, headers=headers, method='GET')
                print('****status_code_time', channel, time.time() - start)
                for data in api_result.get('data', []):
                    """
                    {
                        'codes': {'200': 207268, '2xx': 207268},
                        'time': '1566463800'
                    }
                    """
                    timestamp = int(data['time'])
                    time_key = timestamp_to_str(
                        timestamp, _format='%Y-%m-%d %H:%M')

                    codes = data['codes']

                    if time_key in code_result:
                        for code in codes:
                            if code in code_result[time_key]:
                                code_result[time_key][code] += codes[code]
                            else:
                                if not code.endswith('xx'):
                                    code_result[time_key][other] += codes[code]

                        for code in codes:
                            if code in base_trend:
                                trend_result[time_key][code] += codes[code]


            status = True
        except Exception as e:
            print(e)

        result['code_result'] = code_result
        result['trend_result'] = trend_result

        return status, result

    @staticmethod
    async def domain_log(args):
        """
        日志
        :param args:
        :return:
        """
        domain = args.get('domain', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')

        channel_doc_list = await CCAPI.get_opt_channel(domain, mongodb)

        result = {}

        # 时间格式转化
        time_format = '%Y%m%d'
        start_time = timestamp_to_str(start_time, _format=time_format)
        end_time = timestamp_to_str(end_time, _format=time_format)

        status = False

        download_host = 'https://dlog.chinacache.com'
        try:
            for channel_doc in channel_doc_list:

                channel_id = channel_doc.get('channel_id')
                channel = channel_doc.get('channel')

                headers = CCAPI.get_sign_header()

                log_url = (
                    'http://openapi.chinacache.com/data/common/show/pub'
                    '?channel_id={}&start_time={}&end_time={}&time_degree=hour'
                    '&cloud_curr_client_name={}'
                ).format(channel_id, start_time, end_time, client_name)

                _, log_result = await web_link(
                    log_url, headers=headers, method='GET')

                log_list = log_result.get('data', [])
                log_list.reverse()

                result.setdefault(channel, [])
                channel_log_list = result[channel]
                for i in log_list:
                    download_uri = i.get('downloadUrl', '')

                    download_url = '%s%s' % (download_host, download_uri)

                    log_dict = {
                        'time': i.get('time', ''),
                        'size': i.get('zipSize', 0),
                        'download_url': download_url,
                    }
                    channel_log_list.append(log_dict)

            status = True
        except Exception as e:
            print(e)

        return status, result

    @staticmethod
    async def create_cert(args):
        """添加证书"""
        cert_name = args.get('cert_name', '')
        cert = args.get('cert', '')
        key = args.get('key', '')
        email = args.get('email', '')
        period = args.get('period', 0)

        user_doc = args.get('user_doc')
        cert_db = args.get('cert_db')

        client_name = user_doc.get('cms_username')

        body = {
            "cert_name": cert_name,
            "content": cert,
            "private_key": key,
            "warning_mail": email,
            "warning_period": period,
            "private_key_id": "",
        }

        headers = CCAPI.get_sign_header()

        cert_url = (
            'http://openapi.chinacache.com/cloud-ca/certification/upload?'
            'cloud_curr_client_name={}'
        ).format(client_name)

        status = False
        result = {}
        err_msg = ''
        cert_id = ''

        send_status = 0
        send_error = False
        try:
            _, cert_result = await web_link(
                cert_url, headers=headers, body=body)
            """
            {
                'status': 0,
                'msg': '请求成功', 
                'data': {
                    'cert_id': '5d6cc7ed472537472f5ea3b7',
                    'cert_name': 'xz_test_0001',
                    'is_fc': False
                }
            }
            """
            if cert_result['status'] != 0:
                err_msg = cert_result.get('msg', '')
                send_status = 2
                send_error = True
                assert False
            else:
                cert_id = cert_result['data']['cert_id']
                if cert_id:
                    result['cert_id'] = cert_id
                    send_status = 1

            status = True
        except AssertionError:
            result = err_msg

        except Exception as e:
            result = e
            print(e)

        search_sql = {
            'cert_name': cert_name,
        }
        cert_info = await cert_db.find_one(search_sql)

        send_status_doc = cert_info.get('send_status', {})
        send_status_doc.update({'CC': send_status})

        send_info = cert_info.get('send_info', {})
        send_info.update({
                'CC': {
                    'cms_username': client_name,
                    'cert_name': cert_name,
                    'cert_id': cert_id
                }
        })

        update_doc = {
            'send_status': send_status_doc,
            'send_info': send_info
        }

        if send_error:
            update_doc['status'] = 2

        await cert_db.update_one(search_sql, {'$set': update_doc})

        return status, result


    @staticmethod
    async def delete_cert(args):
        """删除证书"""
        print("*****delete sslcert*****")

        cert_doc = args.get('cert_doc', '')

        cert_id = cert_doc.get('send_info', {}).get('CC', {}).get('cert_id', '')

        user_doc = args.get('user_doc')

        client_name = user_doc.get('cms_username')

        headers = CCAPI.get_sign_header()

        status = False
        result = ''

        try:
            url = (
                "http://openapi.chinacache.com/cloud-ca/config/certificates/{}?"
                "cloud_curr_client_name={}"
            ).format(cert_id, client_name)

            _, cert_result = await web_link(
                url, headers=headers, method="DELETE")
            """
            {'status': 0, 'msg': '请求成功'}
            """
            if cert_result['status'] != 0:
                err_msg = cert_result.get('msg', '')
                assert False

            status = True
        except AssertionError:
            result = err_msg


        return status, result


    @staticmethod
    async def disable_domain(args):
        """域名下线"""
        print('**********disable_domain***********')
        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        domain_list = args.get('domain', [])
        client_name = user_doc.get('cms_username')

        search_sql = {
            'domain': {'$in': domain_list}
        }

        channel_ids = []
        cc_task_db = mongodb.CC_CDN_domain_info
        async for doc in cc_task_db.find(search_sql):
            channel_id = doc.get('channel_id', '')
            if channel_id:
                channel_ids.append(channel_id)

        status = False

        result = {}
        try:
            if not channel_ids:
                status = True
                assert False

            headers = CCAPI.get_sign_header()

            url = (
                'http://openapi.chinacache.com/cloud-papi2/config/'
                'channels/state?cloud_curr_client_name={}'
            ).format(client_name)

            body = {
                "channel_ids": channel_ids,
                "state": "CUSPAUSE",
            }
            body = json.dumps(body)

            # print('url:', url)
            # print('body:', body)

            code, api_result = await web_link(
                url, headers, body=body,  method='PUT')
            """
            {'status': 1, 'error_code': '111403', 'msg': '没有此频道'}
            {'status': 0, 'msg': 'Request success', 
            'data': {'oper_accept': '9801840'}}
            """
            # print('api_result', api_result)
            if not code:
                assert False

            search_sql = {
                'domain': {'$in': domain_list}
            }
            update_doc = {
                'status': 4,
                'modify_time': datetime.datetime.now()
            }

            await cc_task_db.update_many(search_sql, {'$set': update_doc})

            if api_result.get('status') != 0:
                result = api_result.get('msg', '')
                assert False

            result = api_result
            status = True
        except AssertionError:
            pass

        except Exception as e:
            print(e)


        return status, result

    @staticmethod
    async def active_domain(args):
        """域名激活"""

        domain_list = args.get('domain', [])

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')

        search_sql = {
            'domain': {'$in': domain_list}
        }

        check_domain = []
        channel_ids = []
        cc_task_db = mongodb.CC_CDN_domain_info

        async for doc in cc_task_db.find(search_sql):
            channel_id = doc.get('channel_id', '')
            status = doc.get('status')
            domain = doc.get('domain', '')
            if channel_id and status == 4:
                channel_ids.append(channel_id)
                check_domain.append(domain)

        status = False

        result = {}
        try:
            if not channel_ids:
                status = True
                assert False

            headers = CCAPI.get_sign_header()

            url = (
                'http://openapi.chinacache.com/cloud-papi2/config/'
                'channels/state?cloud_curr_client_name={}'
            ).format(client_name)

            body = {
                "channel_ids": channel_ids,
                "state": "COMMERCIAL",
            }
            body = json.dumps(body)

            # print('url:', url)
            # print('body:', body)
            code, api_result = await web_link(
                url, headers, body=body,  method='PUT')

            # print('api_result:', api_result)
            """
            {'status': 0, 'msg': '请求成功', 'data': {'oper_accept': '9802901'}}
            """
            if not code:
                assert False

            if api_result.get('status') != 0:
                result = api_result.get('msg', '')
                assert False

            task_id = api_result['data']['oper_accept']

            task_search_sql = {
                'domain': {'$in': check_domain},
            }

            task_doc = {
                'status': 7,
                'task_id': task_id,
                'task_progress': 0,
                'modify_time': datetime.datetime.now()
            }

            await cc_task_db.update_many(task_search_sql, {"$set": task_doc})

            result = api_result

            status = True
        except AssertionError:
            pass

        except Exception as e:
            print(e)

        return status, result


    @staticmethod
    async def get_channel_conf(channel, cms_name):
        """获取cc配置"""

        headers = CCAPI.get_sign_header()

        url = (
            "http://openapi.chinacache.com/cloud-pbase/channels"
            "?cloud_curr_client_name={}"
        ).format(cms_name)

        code, api_result = await web_link(url, headers, method='GET')


        channel_id = ''
        for i in api_result.get('data', []):
            if channel == i.get('channel_name', ''):
                channel_id = i.get('channel_id', '')
                break

        params = {
            "ROOT": {
                "BODY": {
                    "BUSI_INFO": {
                        "CHN_ID": channel_id,
                        "CODE": "CN001300"
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

        url = 'http://cms3-apir.chinacache.com/apir/9040/qryChnConf'

        print(url)
        print(params)

        code, res = await web_link(url, headers=headers, body=params)


        res_body = res.get('ROOT', {}).get('BODY', {})
        if res_body.get('RETURN_CODE', '') != '0':
            err_msg = res_body.get('RETURN_MSG', '')
            assert False

        out_data = res_body.get('OUT_DATA', {})

        # 回源信息
        src_conf = out_data.get('SOURCE_CONF', [])[0]

        back_type = src_conf.get('backType', 'IPCOMMONCONFIG')
        src_type = ''
        if back_type == 'IPCOMMONCONFIG':
            src_type = 'ip'
        elif back_type == 'ORIGDOMAIN':
            src_type = 'dmn'

        back_ips = src_conf.get('backIps', [])
        back_domain = src_conf.get('backDmns', '')

        # 回源host
        func_conf = out_data.get('FUNC_CONF_INFO', {})
        back_host = ''
        back_hosts = func_conf.get('CN008400', [])
        if back_hosts:
            back_host = back_hosts[0].get(
                'params', {}).get('input_public_hostHeader', '')

        result = {
            'src_type': src_type,
            'src_host': back_host,
            'src_ips': back_ips,
            'src_domain': back_domain
        }

        return result


    @staticmethod
    async def domain_flux_batch(args):
        """
        计费数据
        :param args:
        :return: 返回流量单位(MB)
        """
        def def_handle_api_data(api_data, source_data):
            """处理api返回数据"""
            api_data_dict = {}
            for flux_data in api_data:
                _key = datetime.datetime.strptime(
                    flux_data, '%Y%m%d%H%M').strftime("%Y-%m-%d %H:%M")
                api_data_dict[_key] = [
                    round((api_data[flux_data]*300/8/1000)/1000,6),
                    round((source_data[flux_data]*300/8/1000)/1000,6)
                ]
            return api_data_dict

        domains = args.get('domains', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')
        remove_upper_layer = user_doc.get('remove_upper_layer')

        channel_doc_list = await CCAPI.get_opt_channels(domains, mongodb)

        # 全部时间节点
        time_list = get_time_list(start_time, end_time)

        # 时间格式转化
        time_format = '%Y%m%d'
        start_time = timestamp_to_str(start_time, _format=time_format)
        end_time = timestamp_to_str(end_time, _format=time_format)

        result = {}

        for time_key in time_list:
            result.setdefault(time_key, [0, 0])

        status = False
        try:
            channel_ids = []
            for channel_doc in channel_doc_list:
                channel_id = channel_doc.get('channel_id')
                channel_id_parm = 'channel_id={}'.format(channel_id)
                channel_ids.append(channel_id_parm)

            channel_id_parm = '&'.join(channel_ids)
            headers = CCAPI.get_sign_header()
            cdn_url = (
                'http://openapi.chinacache.com/cloud-bill/bandwidth?'
                'start_time={}&end_time={}&{}&show_time=true'
                '&cloud_curr_client_name={}'
            ).format(start_time, end_time, channel_id_parm, client_name)

            if remove_upper_layer:
                cdn_url += '&layer_type=EDGE'

            start = time.time()
            _, cdn_result = await web_link(
                cdn_url, headers=headers, method='GET')
            print(cdn_url)
            print('******************cdn_flux_time', time.time()-start)

            headers = CCAPI.get_sign_header()
            src_url = (
                'http://openapi.chinacache.com/cloud-bill/bandwidth/'
                'source?start_time={}&end_time={}&{}&show_time=true'
                '&cloud_curr_client_name={}'
            ).format(start_time, end_time, channel_id_parm, client_name)

            start = time.time()
            _, src_result = await web_link(src_url, headers, method='GET')
            print(src_url)
            print('******************src_flux_time', time.time() - start)

            channel_result = def_handle_api_data(
                cdn_result['data'][0]['detail_data'][0]['bandwidths'],
                src_result['data'][0]['detail_data'][0]['bandwidths']
            )

            for key in result:
                if key in channel_result:
                    result[key][0] += channel_result[key][0]
                    result[key][1] += channel_result[key][1]
            status = True
        except Exception as e:
            print(e)

        return status, result

    @staticmethod
    async def domain_status_code_batch(args):
        """
        批量状态码数据
        :param args:
        :return:
        """

        domains = args.get('domains', '')
        start_time = args.get('start_time')
        end_time = args.get('end_time')

        user_doc = args.get('user_doc')
        mongodb = args.get('mongodb')

        client_name = user_doc.get('cms_username')

        # 通信api时间格式转换
        time_format = '%Y%m%d'
        end_time_str = timestamp_to_str(end_time, _format=time_format)
        start_time_str = timestamp_to_str(start_time, _format=time_format)

        result = {}

        status = False

        channel_doc_list = await CCAPI.get_opt_channels(domains, mongodb)
        channel_ids = []
        for channel_doc in channel_doc_list:
            channel_id = channel_doc.get('channel_id')
            channel_id_parm = 'channel_id={}'.format(channel_id)
            channel_ids.append(channel_id_parm)

        channel_id_parm = '&'.join(channel_ids)

        headers = CCAPI.get_sign_header()
        try:
            code_url = (
                'http://openapi.chinacache.com/data/statistics/channel/'
                'code?start_time={}&end_time={}&{}&cloud_curr_client_name={}'
            ).format(start_time_str, end_time_str, channel_id_parm, client_name)

            start = time.time()
            _, code_result = await web_link(
                code_url, headers=headers, method='GET')
            print(code_url)
            print('******************request_time', time.time() - start)
            print(code_result)
            """
            {
                'data': [{
                    'time': '20191011',
                    'detail_data': [
                        {
                            'code': '200',
                            'detail_data': {
                                'flux': 138851494,
                                'request': 1786
                            }
                        }, 
                    
                        {
                            'code': '5XX',
                            'detail_data': {
                                'flux': 0,
                                'request': 0
                            }
                        }
                    ]
                }],
                'status': 0,
                'msg': 'success'
            }
            
            """

            status = True
        except Exception as e:
            print(e)

        return status, result