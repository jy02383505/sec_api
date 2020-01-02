import sys
import asyncio
import copy
import json
import time
import base64
import uuid
import datetime

from sanic import Blueprint
from sanic.response import json as sanic_json
from sanic.response import html
from jinja2 import Environment, PackageLoader, select_autoescape
import logging
from sanic.log import logger

from fuse_api.API import ExternalAPI
from lib.api_conf import FuseApiConfig
from lib.util import (datetime_to_str, get_md5_flag, nsq_writer, sync_dns_del,
                      timestamp_to_datetime)


log = logging.getLogger(__name__)

cdn_bp = Blueprint('cdn', url_prefix='cdn')

# 开启异步特性  要求3.6+
enable_async = sys.version_info >= (3, 6)

# jinjia2 config
env = Environment(
    loader=PackageLoader('views.base', '../templates'),
    autoescape=select_autoescape(['html', 'xml', 'tpl']),
    enable_async=enable_async)


async def template(tpl, **kwargs):
    template = env.get_template(tpl)
    rendered_template = await template.render_async(**kwargs)
    return html(rendered_template)


@cdn_bp.route("/internal/cdn/test/", methods=['POST'])
async def test(request):

    opts = ['CC']
    args = {'domain': 'www.baidu.com'}
    await ExternalAPI.create_domain(opts, **args)

    res = {
        'return_code': 0
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/create_domain/", methods=['POST'])
async def cdn_create_domain(request):
    """创建域名
    task_db
        status
            1 添加配置中
            2 加速中
            3 修改配置中
            4 报停
            -1 异常
    """
    mongodb = request.app.M
    domain_db = mongodb.domain
    user_db = mongodb.user_profile

    task_info = request.json

    protocol_list = task_info.get('protocol', [])
    base_template_id = task_info.get('base_template_id', '')
    domain = task_info.get('domain', '')
    user_id = task_info.get('user_id', '')
    cdn_type = task_info.get('cdn_type', '')
    contract_name = task_info.get('contract_name', '')
    src_type = task_info.get('src_type', '')
    src_ips = task_info.get('src_ips', [])
    src_domain = task_info.get('src_domain', '')
    src_host = task_info.get('src_host', '')
    src_back_type = task_info.get('src_back_type', '')
    src_back_ips = task_info.get('src_back_ips', '')
    src_back_domain = task_info.get('src_back_domain', '')
    ignore_cache_control = task_info.get('ignore_cache_control', '0')
    ignore_query_string = task_info.get('ignore_query_string', '0')
    cache_rule = task_info.get('cache_rule', {})

    crt_name = task_info.get('cert_name', '')

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)

    return_code = 1
    msg = ''

    try:
        args = {
            'mongodb': mongodb,
            'user_doc': user_doc,

            'domain': domain,
            'protocol': protocol_list,
            'crt_name': crt_name,
            'cdn_type': cdn_type,

            'src_type': src_type,
            'src_ips': src_ips,
            'src_domain': src_domain,

            'src_back_type': src_back_type,
            'src_back_ips': src_back_ips,
            'src_back_domain': src_back_domain,

            'src_host': src_host,

            'ignore_cache_control': ignore_cache_control,
            'ignore_query_string': ignore_query_string,

            'cache_rule': cache_rule,

            'base_template_id': base_template_id,
            'contract_name': contract_name,
        }


        cdn_opt = user_doc.get('cdn_opt', '')

        result = await ExternalAPI.create_domain(cdn_opt, args)

        for opt in cdn_opt:

            if not result[opt][0]:
                msg = 'opt %s error %s' % (opt, result[opt][1])
                logger.info(msg)
                assert False

        for protocol in protocol_list:
            domain_search_sql = {
                "domain": domain,
                "protocol": protocol,
            }

            domain_doc = {
                "domain": domain,
                "protocol": protocol,
                "user_id": user_id,
                "create_time": datetime.datetime.now(),
                "cdn": cdn_opt
            }

            old_doc = await domain_db.find_one(domain_search_sql)
            if not old_doc:
                await domain_db.insert_one(domain_doc)
            else:
                await domain_db.update_many(
                    domain_search_sql, {"$set": domain_doc})

        return_code = 0
    except Exception as e:
        print(e)

    res = {
        'return_code': return_code,
        'msg': msg
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/edit_domain/", methods=['POST'])
async def cdn_edit_domain(request):
    """修改域名"""

    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain = task_info.get('domain', '')
    user_id = task_info.get('user_id', '')

    crt_name = task_info.get('cert_name', '')

    src_type = task_info.get('src_type', '')
    src_ips = task_info.get('src_ips', [])
    src_domain = task_info.get('src_domain', '')

    src_host = task_info.get('src_host', '')

    src_back_type = task_info.get('src_back_type', '')
    src_back_ips = task_info.get('src_back_ips', '')
    src_back_domain = task_info.get('src_back_domain', '')

    ignore_cache_control = task_info.get('ignore_cache_control', '0')
    ignore_query_string = task_info.get('ignore_query_string', '0')
    cache_rule = task_info.get('cache_rule', {})

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)

    cdn_opt = user_doc.get('cdn_opt', '')

    args = {
        'user_doc': user_doc,
        'mongodb': mongodb,
        'domain': domain,
        'crt_name': crt_name,

        'src_type': src_type,
        'src_ips': src_ips,
        'src_domain': src_domain,

        'src_host': src_host,

        'src_back_type': src_back_type,
        'src_back_ips': src_back_ips,
        'src_back_domain': src_back_domain,

        'ignore_cache_control': ignore_cache_control,
        'ignore_query_string': ignore_query_string,
        'cache_rule': cache_rule
    }

    return_code = 1
    err_msg = ''
    print(11111111111, args)
    try:
        result = await ExternalAPI.edit_domain(cdn_opt, args)
        """
        {'CC': [False, '频道已经存在不允许开通!频道状态：InitOpen']}
        """

        for opt in cdn_opt:
            if not result[opt][0]:
                err_msg = result[opt][1]
                assert False

        return_code = 0

    except AssertionError:
        pass


    res = {
        'err_msg': err_msg,
        'return_code': return_code
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/query_domain/", methods=['POST'])
async def cdn_query_domain(request):
    """cdn域名查询"""

    mongodb = request.app.M

    task_db = mongodb.CC_CDN_domain_info

    domain_info = request.json

    return_type = domain_info.get('return_type', 'is_dict')

    channel_list = domain_info.get('channel_list', [])
    cdn_type = domain_info.get('cdn_type', '')
    domain_status = domain_info.get('domain_status', [])

    search_sql = {}
    if channel_list:
        search_sql['channel'] = {'$in': channel_list}

    if cdn_type:
        search_sql['cdn_type'] = cdn_type

    if domain_status:
        search_sql['status'] = {'$in': domain_status}

    if return_type == 'is_list':
        result_domain_query = []
    elif return_type == 'is_dict':
        result_domain_query = {}

    async for doc in task_db.find(search_sql):
        temp_doc = copy.deepcopy(doc)
        temp_doc.pop('_id')

        if return_type == 'is_list':
            result_domain_query.append(temp_doc)
        elif return_type == 'is_dict':
            result_domain_query[temp_doc['channel']] = temp_doc

    res = {'domain_query': result_domain_query}

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_flux/", methods=['POST'])
async def cdn_domain_flux(request):
    """域名计费数据"""
    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain_list = task_info.get('domain_list', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    opts = task_info.get('opts', [])

    sep = task_info.get('sep', False)

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    if not opts:
        opts = user_doc.get('cdn_opt', '')

    return_code = 1

    result_list = {}

    try:
        task = []
        for domain in domain_list:

            args = {
                'user_doc': user_doc,
                'mongodb': mongodb,
                'domain': domain,
                'start_time': start_time,
                'end_time': end_time

            }

            task.append(ExternalAPI.domain_flux(opts, args))

        res_list = await asyncio.gather(*task)

        for all_opt_flux in res_list:

            """
            {
                'CC': [True, {
                    '2019-08-22 16:50': [39513.282487000004, 0.018225],
                    '2019-08-22 16:55': [39568.210462999996, 0.006975],
                    '2019-08-22 17:00': [39733.214776, 0.00375]
                }]
            }
            """
            if sep:
                result = {}
                temp_flux = []

                for opt in all_opt_flux:

                    if not all_opt_flux[opt][0]:
                        continue

                    result.setdefault(opt, [])

                    data = all_opt_flux[opt][1]
                    for t in data:
                        flux_dict = {
                            'time_key': t,
                            'cdn_data': data[t][0],
                            'src_data': data[t][1]
                        }
                        temp_flux.append(flux_dict)
                    else:
                        temp_flux = sorted(
                            temp_flux, key=lambda x: x['time_key'])
                        result[opt] = temp_flux
            else:
                result = []
                temp_flux = {}

                for opt in all_opt_flux:
                    if not all_opt_flux[opt][0]:
                        continue

                    for t in all_opt_flux[opt][1]:
                        temp_flux.setdefault(t, [0, 0])
                        temp_flux[t][0] += all_opt_flux[opt][1][t][0]
                        temp_flux[t][1] += all_opt_flux[opt][1][t][1]

                for time_key in temp_flux:
                    flux_dict = {
                        'time_key': time_key,
                        'cdn_data': temp_flux[time_key][0],
                        'src_data': temp_flux[time_key][1]
                    }
                    result.append(flux_dict)
                else:
                    result = sorted(result, key=lambda x: x['time_key'])

            result_list[domain] = result

        return_code = 0

    except Exception as e:
        logger.info(e)

    res = {
        'return_code': return_code,
        'result': result_list
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_request/", methods=['POST'])
async def cdn_domain_request(request):
    """域名请求量数据"""
    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain_list = task_info.get('domain_list', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    opts = task_info.get('opts', [])

    sep = task_info.get('sep', False)

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    if not opts:
        opts = user_doc.get('cdn_opt', '')

    result_list = {}
    return_code = 1

    try:
        task = []
        for domain in domain_list:

            args = {
                'user_doc': user_doc,
                'mongodb': mongodb,
                'domain': domain,
                'start_time': start_time,
                'end_time': end_time

            }
            task.append(ExternalAPI.domain_request(opts, args))

        res_list = await asyncio.gather(*task)

        for opt_request in res_list:

            """
            {
                'CC': [True, {
                    '2019-08-22 16:50': {
                        'requests': 405364,
                        'hit': 405276,
                        'miss': 88
                    },
                }]
            }
            """

            if sep:
                result = {}
                temp_data = []

                for opt in opt_request:

                    if not opt_request[opt][0]:
                        continue

                    result.setdefault(opt, [])

                    data = opt_request[opt][1]
                    for t in data:
                        flux_dict = {
                            'time_key': t,
                        }
                        for k in data[t]:
                            flux_dict[k] = data[t][k]

                        temp_data.append(flux_dict)
                    else:
                        temp_data = sorted(
                            temp_data, key=lambda x: x['time_key'])
                        result[opt] = temp_data

            else:
                result = []
                temp_data = {}
                for opt in opt_request:
                    if not opt_request[opt][0]:
                        continue

                    for t in opt_request[opt][1]:
                        temp_data.setdefault(
                            t, {'requests': 0, 'hit': 0, 'miss': 0})

                        for c in temp_data[t]:
                            temp_data[t][c] += opt_request[opt][1][t][c]

                for time_key in temp_data:
                    request_dict = copy.deepcopy(temp_data[time_key])
                    request_dict['time_key'] = time_key
                    result.append(request_dict)

                result = sorted(result, key=lambda x: x['time_key'])

            result_list[domain] = result

            return_code = 0
    except Exception as e:
        print(e)

    res = {
        'return_code': return_code,
        'result': result_list
    }
    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_status_code/", methods=['POST'])
async def cdn_domain_status_code(request):
    """域名请求量数据"""
    start = time.time()
    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain_list = task_info.get('domain_list', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    opts = task_info.get('opts', [])

    sep = task_info.get('sep', False)

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    if not opts:
        opts = user_doc.get('cdn_opt', '')

    result_list = {}
    trend_result_list = {}
    return_code = 1

    sc_config = FuseApiConfig.STATUS_CODES

    try:
        start = time.time()
        task = []
        for domain in domain_list:

            args = {
                'user_doc': user_doc,
                'mongodb': mongodb,
                'domain': domain,
                'start_time': start_time,
                'end_time': end_time,

            }

            task.append(ExternalAPI.domain_status_code(opts, args))

        res_list = await asyncio.gather(*task)
        # print(res_list)

        print(6666666666, time.time()-start)

        for opt_code in res_list:

            # opt_code = await ExternalAPI.domain_status_code(opts, args)
            #
            # """
            # {
            #     'CC': [False, {
            #         '2019-08-22 16:50': {
            #             '200': 402870,
            #             '206': 0,
            #             '302': 0,
            #             '304': 0,
            #             '403': 0,
            #             '404': 0,
            #             '5xx': 0,
            #             'other': 0
            #         },
            #     }]
            # }
            # """
            #
            if sep:
                result = {}
                temp_data = []

                trend_result = {}
                trend_temp_data = []

                for opt in opt_code:

                    if not opt_code[opt][0]:
                        continue

                    result.setdefault(opt, [])
                    code_result = opt_code[opt][1].get('code_result', {})
                    for t in code_result:
                        flux_dict = {
                            'time_key': t,
                        }
                        for k in code_result[t]:
                            flux_dict[k] = code_result[t][k]

                        temp_data.append(flux_dict)
                    else:
                        temp_data = sorted(
                            temp_data, key=lambda x: x['time_key'])
                        result[opt] = temp_data

                    trend_result.setdefault(opt, [])
                    trend_code_result = opt_code[opt][1].get('trend_result', {})
                    for t in trend_code_result:
                        flux_dict = {
                            'time_key': t,
                        }
                        for k in trend_code_result[t]:
                            flux_dict[k] = trend_code_result[t][k]

                        trend_temp_data.append(flux_dict)
                    else:
                        trend_temp_data = sorted(
                            trend_temp_data, key=lambda x: x['time_key'])
                        trend_result[opt] = trend_temp_data

            else:
                result = []

                sum_code = {}

                trend_result = []

                trend_sum_code = {}

                for opt in opt_code:
                    if not opt_code[opt][0]:
                        continue

                    code_result = opt_code[opt][1].get('code_result', {})
                    for t in code_result:
                        sum_code.setdefault(
                            t, copy.deepcopy(sc_config['base_code']))

                        for c in sum_code[t]:
                            sum_code[t][c] += opt_code[opt][1][t][c]

                    trend_result = opt_code[opt][1].get('trend_result', {})
                    for t in trend_result:
                        trend_sum_code.setdefault(t, {})
                        for c in trend_result[t]:
                            trend_sum_code[t].setdefault(c, 0)
                            trend_sum_code[t][c] += trend_result[t][c]

                for time_key in sum_code:
                    code_dict = copy.deepcopy(sum_code[time_key])
                    code_dict['time_key'] = time_key
                    result.append(code_dict)
                result = sorted(result, key=lambda x: x['time_key'])

                for time_key in trend_sum_code:
                    code_dict = copy.deepcopy(trend_sum_code[time_key])
                    code_dict['time_key'] = time_key
                    trend_result.append(code_dict)
                trend_result = sorted(trend_result, key=lambda x: x['time_key'])

            result_list[domain] = result
            trend_result_list[domain] = trend_result
            """
            {
                'CC': [
                    True,
                    {'2019-09-01 00:00':
                    {'2xx': 241054, '3xx': 28, '4xx': 0, '5xx': 0}
                ]
            }
            """
        return_code = 0
    except Exception as e:
        print(e)
    print('--------------------', time.time()-start)
    res = {
        'return_code': return_code,
        'result': result_list,
        'trend_result': trend_result_list
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_log/", methods=['POST'])
async def cdn_domain_log(request):
    """域名日志"""

    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain = task_info.get('domain', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    return_code = 0

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    cdn_opt = user_doc.get('cdn_opt', '')

    args = {
        'user_doc': user_doc,
        'mongodb': mongodb,
        'domain': domain,
        'start_time': start_time,
        'end_time': end_time
    }

    opt_log = await ExternalAPI.domain_log(cdn_opt, args)

    result = {}
    try:
        for opt in opt_log:
            if not opt_log[opt][0]:
                continue

            result = opt_log[opt][1]
        return_code = 0
    except Exception as e:
        print(e)


    res = {
        'return_code': return_code,
        'result': result
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_sync_conf/", methods=['POST'])
async def cdn_domain_sync_conf(request):
    """同步域名配置"""

    mongodb = request.app.M
    domain_db = mongodb.domain
    user_db = mongodb.user_profile

    task_info = request.json

    domain = task_info.get('domain', '')
    protocol = task_info.get('protocol', '')
    user_id = task_info.get('user_id', '')
    provider = task_info.get('provider', '')

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)

    cdn_opt = user_doc.get('cdn_opt', '')

    domain_search_sql = {
        'domain': domain,
        'protocol': protocol
    }
    domain_doc = await domain_db.find_one(domain_search_sql)

    create_time = domain_doc.get('create_time')

    create_time = datetime_to_str(create_time, _format='%Y-%m-%d %H:%M')

    domain_result = {
        'domain': domain,
        'protocol': protocol,
        'user_id': user_id,
        'create_time': create_time
    }

    return_code = 1

    try:
        args = {
            'mongodb': mongodb,
            'domain': domain,
            'protocol': protocol
        }
        result = await ExternalAPI.sync_domain_conf(cdn_opt, args)

        for opt in cdn_opt:
            if opt != provider:
                continue

            if not result[opt][0]:
                msg = 'opt %s error %s' % (opt, result[opt][1])
                logger.info(msg)
                assert False

            domain_conf = result[opt][1]
            domain_result.update(domain_conf)


        return_code = 0
    except Exception as e:
        print(e)

    res = {
        'return_code': return_code,
        'domain_conf': domain_result
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_refresh/", methods=['POST'])
async def cdn_domain_refresh(request):
    """域名刷新"""

    return_code = 1
    result = {}

    mongodb = request.app.M
    user_db = mongodb.user_profile
    task_db = mongodb.refresh_task
    log_db = mongodb.refresh_log

    task_info = request.json

    user_id = task_info.get('user_id', '')
    urls = task_info.get('urls', [])
    dirs = task_info.get('dirs', [])

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    cdn_opt = user_doc.get('cdn_opt', '')
    username = user_doc.get('username', '')
    cms_username = user_doc.get('cms_username', '')
    cms_password = user_doc.get('cms_password', '')
    user_id = user_doc.get('user_id', '')

    refresh_log_flag = get_md5_flag()
    now = datetime.datetime.now()

    nsq_params = {
        'flag': refresh_log_flag,
        "cms_username": cms_username,
        'urls': urls,
        'dirs': dirs,
    }

    nsq_params = json.dumps(nsq_params)

    send_status = {}
    try:
        for opt in cdn_opt:
            nsq_name = 'cdn_%s_%s' % (opt.lower(), 'refresh')
            send_flag = await nsq_writer(nsq_name, nsq_params)
            if not send_flag:
                send_status[opt] = 0
                logger.error('%s %s send nsq err' % (refresh_log_flag, opt))

        task_doc = {
            "urls": urls,
            "dirs": dirs,
            "start_time": now,
            "status": 0,
            "flag": refresh_log_flag,
            "username": username,
            "cms_password": cms_password,
            "cms_username": cms_username,
            "user_id": user_id,
            "send_status": send_status,
            "opts": cdn_opt
        }

        insert_obj = await task_db.insert_one(task_doc)

        if insert_obj:
            for i in urls:
                log_doc = {
                    'url': i,
                    'type': 'url',
                    'status': 0,
                    "start_time": now,
                    "username": username,
                    'flag': refresh_log_flag
                }
                await log_db.insert_one(log_doc)

            for i in dirs:
                log_doc = {
                    'url': i,
                    'type': 'dir',
                    'status': 0,
                    "start_time": now,
                    "username": username,
                    'flag': refresh_log_flag
                }
                await log_db.insert_one(log_doc)

        return_code = 0
        result['task_id'] = refresh_log_flag

    except Exception as e:
        print(e)

    res = {
        'return_code': return_code,
        'result': result
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_refresh_status/", methods=['POST'])
async def cdn_domain_refresh_status(request):
    """域名刷新结果查询"""
    return_code = 1
    result = {}

    mongodb = request.app.M

    log_db = mongodb.refresh_log

    task_info = request.json

    username = task_info.get('username', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')
    url = task_info.get('url', '')
    refresh_type = task_info.get('type', '')
    status = task_info.get('status', '')

    start_time = timestamp_to_datetime(start_time)
    end_time = timestamp_to_datetime(end_time)

    log_search_sql = {
        'start_time': {
            "$gte": start_time,
            "$lte": end_time,
        }
    }

    if username:
        log_search_sql['username'] = username

    if url:
        log_search_sql['url'] = url

    if refresh_type:
        log_search_sql['type'] = refresh_type

    if status:
        log_search_sql['status'] = status


    result_list = []
    try:
        async for doc in log_db.find(log_search_sql):

            start_time = doc.get('start_time', '')
            start_time = datetime_to_str(start_time, _format='%Y-%m-%d %H:%M')

            log_dict = {
                'url': doc.get('url', ''),
                'type': doc.get('type', ''),
                'start_time': start_time,
                'status': doc.get('status', '')
            }
            result_list.append(log_dict)

        result_list = sorted(
            result_list, key=lambda x: x['start_time'], reverse=True)

        return_code = 0

    except Exception as e:
        print(e)

    result['return_code'] = return_code
    result['result_list'] = result_list

    return sanic_json(result)


@cdn_bp.route("/internal/cdn/domain_preload/", methods=['POST'])
async def cdn_domain_preload(request):
    """域名预热"""

    return_code = 1
    result = {}

    mongodb = request.app.M
    user_db = mongodb.user_profile
    task_db = mongodb.preload_task
    log_db = mongodb.preload_log

    task_info = request.json

    user_id = task_info.get('user_id', '')
    urls = task_info.get('urls', [])

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    cdn_opt = user_doc.get('cdn_opt', '')
    username = user_doc.get('username', '')
    cms_username = user_doc.get('cms_username', '')
    cms_password = user_doc.get('cms_password', '')
    user_id = user_doc.get('user_id', '')

    preload_log_flag = get_md5_flag()
    now = datetime.datetime.now()

    nsq_params = {
        "flag": preload_log_flag,
        "cms_username": cms_username,
        "cms_password": cms_password,
        'urls': urls,
    }
    nsq_params = json.dumps(nsq_params)

    send_status = {}
    try:
        for opt in cdn_opt:
            nsq_name = 'cdn_%s_%s' % (opt.lower(), 'preload')
            send_flag = await nsq_writer(nsq_name, nsq_params)
            if not send_flag:
                send_status[opt] = 0
                logger.error('%s %s send nsq err' % (preload_log_flag, opt))

        task_doc = {
            "urls": urls,
            "start_time": now,
            "status": 0,
            "flag": preload_log_flag,
            "username": username,
            "cms_password": cms_password,
            "cms_username": cms_username,
            "user_id": user_id,
            "send_status": send_status,
            "opts": cdn_opt
        }

        insert_obj = await task_db.insert_one(task_doc)

        if insert_obj:
            for i in urls:
                log_doc = {
                    'url': i,
                    'type': 'url',
                    'status': 0,
                    "start_time": now,
                    "username": username,
                    'flag': preload_log_flag
                }
                await log_db.insert_one(log_doc)

        return_code = 0
        result['task_id'] = preload_log_flag

    except Exception as e:
        print(e)

    res = {
        'return_code': return_code,
        'result': result
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_preload_status/", methods=['POST'])
async def cdn_domain_preload_status(request):
    """域名预热结果查询"""
    return_code = 1
    result = {}

    mongodb = request.app.M

    log_db = mongodb.preload_log

    task_info = request.json

    username = task_info.get('username', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')
    url = task_info.get('url', '')
    status = task_info.get('status', '')

    start_time = timestamp_to_datetime(start_time)
    end_time = timestamp_to_datetime(end_time)

    log_search_sql = {
        'start_time': {
            "$gte": start_time,
            "$lte": end_time,
        }
    }

    if username:
        log_search_sql['username'] = username

    if url:
        log_search_sql['url'] = url

    if status:
        log_search_sql['status'] = status


    result_list = []
    try:
        async for doc in log_db.find(log_search_sql):

            start_time = doc.get('start_time', '')
            start_time = datetime_to_str(start_time, _format='%Y-%m-%d %H:%M')

            log_dict = {
                'url': doc.get('url', ''),
                'start_time': start_time,
                'status': doc.get('status', '')
            }
            result_list.append(log_dict)

        result_list = sorted(
            result_list, key=lambda x: x['start_time'], reverse=True)

        return_code = 0

    except Exception as e:
        print(e)

    result['return_code'] = return_code
    result['result_list'] = result_list

    return sanic_json(result)


@cdn_bp.route("/internal/cdn/disable_domain/", methods=['POST'])
async def cdn_domain_disable(request):
    """域名下线"""
    mongodb = request.app.M
    cname_db = mongodb.domain_cname
    user_db = mongodb.user_profile

    task_info = request.json

    user_id = task_info.get('user_id', '')
    domain_list = task_info.get('domain', [])

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    cdn_opt = user_doc.get('cdn_opt', '')

    args = {
        'domain': domain_list,
        'user_doc': user_doc,
        'mongodb': mongodb
    }

    err_msg = ''
    return_code = 1
    try:
        result = await ExternalAPI.disable_domain(cdn_opt, args)
        """
         {'CC': [True, {'status': 0, 'msg': 'Request success',
         'data': {'oper_accept': '9802013'}}]}
        """

        for opt in cdn_opt:

            if not result[opt][0]:
                msg = 'opt %s error %s' % (opt, result[opt][1])
                logger.info(msg)
                err_msg = 'disable error !'
                assert False
        else:

            send_domain_list = []
            for domain in domain_list:
                sync_result = await sync_dns_del(domain, cname_db)
                print(sync_result)
                logger.info(sync_result)
                if sync_result:
                    send_domain_list.append(domain)

            return_code = 0

    except AssertionError:
        pass

    res = {
        'err_msg': err_msg,
        'return_code': return_code
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/active_domain/", methods=['POST'])
async def cdn_domain_active(request):
    """域名下线"""
    mongodb = request.app.M
    user_db = mongodb.user_profile

    task_info = request.json

    user_id = task_info.get('user_id', '')
    domain_list = task_info.get('domain', [])

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    cdn_opt = user_doc.get('cdn_opt', '')

    args = {
        'domain': domain_list,
        'user_doc': user_doc,
        'mongodb': mongodb
    }

    err_msg = ''
    return_code = 1
    try:
        result = await ExternalAPI.active_domain(cdn_opt, args)
        """
         {'CC': [True, {'status': 0, 'msg': 'Request success',
         'data': {'oper_accept': '9802013'}}]}
        """

        for opt in cdn_opt:

            if not result[opt][0]:
                msg = 'opt %s error %s' % (opt, result[opt][1])
                logger.info(msg)
                err_msg = 'disable error !'
                assert False
        else:
            return_code = 0

    except AssertionError:
        pass

    res = {
        'err_msg': err_msg,
        'return_code': return_code
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/get_nameid/", methods=['GET'])
async def cdn_get_nameid(request):
    """获取全量nameid"""

    data = {
        "ROOT": {
            "HEADER": {
                "ISCOMPRESS": False,
                "OPERTYPE": "RESET",
                "OPERBUSI": False
            },
            "BODY": {
                "taskLineId": str(uuid.uuid4()),
                "datas": [
                    {
                        "busiType": "cdnService",
                        "opers": []
                    }
                ]
            }
        }
    }


    mongodb = request.app.M
    cname_db = mongodb.domain_cname

    name_id_dict = {}
    async for doc in cname_db.find({}):
        domain = doc.get('domain', '')
        other_cname = doc.get('other_cname', '')
        inner_cname = doc.get('inner_cname', '')
        location = doc.get('location', '')
        strategy = doc.get('strategy', '1')
        ttl = doc.get('ttl', '120')
        cname_flag = 'true'

        msg = "%s;%s;%s;%s;%s;%s;%s;%s;%s" % (
            location, cname_flag, inner_cname, '', '', '', '', strategy, ttl)

        if domain in name_id_dict:
            name_id_dict[domain]['value'] += "\n" + msg
        else:
            name_id_dict[domain] = {
                "value": msg,
                "other_cname": other_cname
            }

    for domain in name_id_dict:
        other_cname = name_id_dict[domain].get('other_cname', '')
        value = name_id_dict[domain].get('value', '')

        data['ROOT']['BODY']['datas'][0]["opers"].append({
            "name": other_cname,
            "message": base64.b64encode(
                value.encode(encoding="utf-8")).decode('utf-8'),
            "type": "add"
        })

    return sanic_json(data)


@cdn_bp.route("/internal/cdn/domain_flux_batch/", methods=['POST'])
async def cdn_domain_flux_batch(request):
    """域名计费数据"""
    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain_list = task_info.get('domain_list', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    opts = task_info.get('opts', [])

    sep = task_info.get('sep', False)

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    if not opts:
        opts = user_doc.get('cdn_opt', '')

    return_code = 1

    result_list = {}

    try:
        args = {
            'user_doc': user_doc,
            'mongodb': mongodb,
            'domains': domain_list,
            'start_time': start_time,
            'end_time': end_time

        }
        all_opt_flux = await ExternalAPI.domain_flux_batch(opts, args)

        """
        {
            'CC': [True, {
                '2019-08-22 16:50': [39513.282487000004, 0.018225],
                '2019-08-22 16:55': [39568.210462999996, 0.006975],
                '2019-08-22 17:00': [39733.214776, 0.00375]
            }]
        }
        """
        if sep:
            result = {}
            temp_flux = []

            for opt in all_opt_flux:

                if not all_opt_flux[opt][0]:
                    continue

                result.setdefault(opt, [])

                data = all_opt_flux[opt][1]
                for t in data:
                    flux_dict = {
                        'time_key': t,
                        'cdn_data': data[t][0],
                        'src_data': data[t][1]
                    }
                    temp_flux.append(flux_dict)
                else:
                    temp_flux = sorted(
                        temp_flux, key=lambda x: x['time_key'])
                    result[opt] = temp_flux
        else:
            result = []
            temp_flux = {}

            for opt in all_opt_flux:
                if not all_opt_flux[opt][0]:
                    continue

                for t in all_opt_flux[opt][1]:
                    temp_flux.setdefault(t, [0, 0])
                    temp_flux[t][0] += all_opt_flux[opt][1][t][0]
                    temp_flux[t][1] += all_opt_flux[opt][1][t][1]

            for time_key in temp_flux:
                flux_dict = {
                    'time_key': time_key,
                    'cdn_data': temp_flux[time_key][0],
                    'src_data': temp_flux[time_key][1]
                }
                result.append(flux_dict)
            else:
                result = sorted(result, key=lambda x: x['time_key'])


        return_code = 0

    except Exception as e:
        logger.info(e)

    res = {
        'return_code': return_code,
        'result': result
    }

    return sanic_json(res)


@cdn_bp.route("/internal/cdn/domain_status_code_batch/", methods=['POST'])
async def cdn_domain_status_code_batch(request):
    """域名计费数据"""
    mongodb = request.app.M

    user_db = mongodb.user_profile

    task_info = request.json

    domain_list = task_info.get('domain_list', '')
    user_id = task_info.get('user_id', '')
    start_time = task_info.get('start_time', '')
    end_time = task_info.get('end_time', '')

    opts = task_info.get('opts', [])

    sep = task_info.get('sep', False)

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    if not opts:
        opts = user_doc.get('cdn_opt', '')

    return_code = 1

    result_list = {}

    try:
        args = {
            'user_doc': user_doc,
            'mongodb': mongodb,
            'domains': domain_list,
            'start_time': start_time,
            'end_time': end_time

        }
        all_opt_flux = await ExternalAPI.domain_status_code_batch(opts, args)

        """
        {
            'CC': [True, {
                '2019-08-22 16:50': [39513.282487000004, 0.018225],
                '2019-08-22 16:55': [39568.210462999996, 0.006975],
                '2019-08-22 17:00': [39733.214776, 0.00375]
            }]
        }
        """

        return_code = 0
        result = {}

    except Exception as e:
        logger.info(e)

    res = {
        'return_code': return_code,
        'result': result
    }

    return sanic_json(res)
