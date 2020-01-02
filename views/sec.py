#!/usr/bin/env python
import sys
import copy
import datetime
from sanic import Blueprint
from sanic.response import text, json
from sanic.response import html
from sanic.log import logger
import traceback
from jinja2 import Environment, PackageLoader, select_autoescape
from .waf import activate, create, parseProtocolRecordDomain
import json as J


sec_bp = Blueprint('sec', url_prefix='sec')

# 开启异步特性  要求3.6+
enable_async = sys.version_info >= (3, 6)

# jinjia2 config
env = Environment(
    loader=PackageLoader('views.sec', '../templates'),
    autoescape=select_autoescape(['html', 'xml', 'tpl']),
    enable_async=enable_async)


async def template(tpl, **kwargs):
    template = env.get_template(tpl)
    rendered_template = await template.render_async(**kwargs)
    return html(rendered_template)


@sec_bp.route("/internal/waf_create/", methods=['POST'])
async def waf_create(request):
    """waf基础规则配置信息
    status = [
        ('WAF未配置', 0),
        ('WAF配置中', 1),
        ('WAF配置成功', 2),
        ('接入CDN成功', 3),
        ('WAF配置失败', -1),
    ]
    """
    M = request.app.M
    col_info = M.QINGSONG_waf_info
    col_task = M.QINGSONG_waf_task
    col_domain = M.domain
    data = request.json

    status = 1    # 创建到步骤 1
    res = {
        'return_code': 1,
        'message': '',
        'status': status
    }

    provider = data['provider']
    channel = data['channel']
    domain = data['domain']
    protocol, record, domain0 = parseProtocolRecordDomain(channel)

    # domain_doc_fields = ['domain', 'short_name', 'access_type', 'access_point', 'access_point_cname', 'status']
    domain_doc_fields = ['domain', 'short_name']
    data_domain = {f: data[f] for f in domain_doc_fields}

    logger.debug(f'waf_create[beforePop.] data: {data}')
    [data.pop(k) for k in domain_doc_fields]
    logger.debug(f'waf_create[afterPop.] data: {data}')

    try:
        #---send request to waf app for binding QINGSONG's service.
        rCreate = await create(request, data, provider)
        rCreate = J.loads(str(rCreate.body, 'utf-8'))
        logger.info(f'waf_create rCreate: {rCreate}')
        return_code = rCreate[provider]['return_code']
        message = rCreate[provider].get('message', 'success')
        if return_code != 0:
            res['return_code'] = return_code
            res['message'] = message
            res['status'] = status
            return json(res)

        if rCreate[provider].get('data') is None:
            logger.info(f'waf_create[dataError.] data: {data}')
            res['return_code'] = 2
            res['message'] = message
            res['status'] = 0
            return json(res)
        domain_status = rCreate[provider]['data'].get('status') if return_code == 0 else -9
        DOMAIN_STATUS_MAP = {
            2: 2,
            1: 2,
            0: 1,
            -1: 1,
            -2: -1
        }
        status = DOMAIN_STATUS_MAP[domain_status]
        res['return_code'] = 0
        res['status'] = status
        res['message'] = message
        logger.info(f'waf_create res: {res}')


        search_sql = {
            'domain': domain,
        }

        domain_doc = await col_domain.find_one(search_sql)

        waf_list = domain_doc.get('waf', [])
        if provider not in waf_list:
            waf_list.append(provider)
            logger.info(f'waf_create[providerAppendDone.] data: {data}|| provider: {provider}|| waf_list: {waf_list}')
        else:
            logger.info(f'waf_create[providerHasExistedBefore.] data: {data}|| provider: {provider}|| waf_list: {waf_list}')

        update_domain_doc = {
            'waf': waf_list
        }

        if return_code == 0:
            await col_domain.update_many(search_sql, {"$set": update_domain_doc})

            old_doc = await col_task.find_one(search_sql)
            if not old_doc:
                await col_task.insert_one(data_domain)
            res['return_code'] = return_code
        else:
            await col_task.delete_one(search_sql)
            await col_info.delete_one({'record': record, 'domain': domain0})
            logger.info(f'waf_create[resetMongoDone.] channel: {channel}|| data: {data}')

    except Exception:
        logger.error(traceback.format_exc())
        res['return_code'] = 1
        res['message'] = 'Exceptions Occured.'
        res['status'] = -1

    return json(res)


@sec_bp.route("/internal/waf_binding/", methods=['POST'])
async def waf_binding(request):
    """waf基础规则配置信息
    status = [
        ('WAF未配置', 0),
        ('WAF配置中', 1),
        ('WAF配置成功', 2),
        ('接入CDN成功', 3),
        ('WAF配置失败', -1),
    ]
    """
    mongodb = request.app.M
    waf_task_db = mongodb.QINGSONG_waf_task
    domain_db = mongodb.domain
    task_info = request.json

    task_info['status'] = 3    # 绑定直接到步骤 3

    provider = task_info.pop('provider')
    domain = task_info['domain']

    try:

        search_sql = {
            'domain': domain,
        }

        domain_doc = await domain_db.find_one(search_sql)

        protocol = domain_doc.get('protocol', 'http')

        waf_list = domain_doc.get('waf', [])
        if provider not in waf_list:
            waf_list.append(provider)
            logger.info(f'waf_binding[providerAppendDone.] task_info: {task_info}|| provider: {provider}|| waf_list: {waf_list}')
        else:
            logger.info(f'waf_binding[providerHasExistedBefore.] task_info: {task_info}|| provider: {provider}|| waf_list: {waf_list}')

        update_domain_doc = {
            'waf': waf_list
        }

        await domain_db.update_many(search_sql, {"$set": update_domain_doc})

        old_doc = await waf_task_db.find_one(search_sql)
        if not old_doc:
            await waf_task_db.insert_one(task_info)

        #---send request to waf app for binding QINGSONG's service.
        channel = f'{protocol}://{domain}'
        rActivate = await activate(request, channel)
        logger.info(f'waf_binding rActivate.body: {rActivate.body}')
        rActivate = J.loads(str(rActivate.body, 'utf-8'))
        return_code = rActivate[provider]['return_code']

    except Exception:
        logger.error(traceback.format_exc())
        return_code = 1

    res = {
        'return_code': return_code
    }

    return json(res)


@sec_bp.route("/internal/waf_set_cdn/", methods=['POST'])
async def waf_set_cdn(request):
    """waf 移除cdn
    status = [
        ('WAF未配置', 0),
        ('WAF配置中', 1),
        ('WAF配置成功', 2),
        ('接入CDN成功', 3),
        ('WAF配置失败', -1),
    ]
    """

    mongodb = request.app.M
    waf_task_db = mongodb.QINGSONG_waf_task
    task_info = request.json

    domain = task_info['domain']
    switch = task_info['switch']
    confirm_cdn_preload = task_info['confirm_cdn_preload']
    confirm_cdn_http_layered = task_info['confirm_cdn_http_layered']
    confirm_cdn_https_layered = task_info['confirm_cdn_https_layered']

    try:

        search_sql = {
            'domain': domain,
            'status': 2 if switch == 1 else 3,
        }

        update_status = 3 if switch == 1 else 2

        update_task_doc = {
            'confirm_cdn_preload': confirm_cdn_preload,
            'confirm_cdn_http_layered': confirm_cdn_http_layered,
            'confirm_cdn_https_layered': confirm_cdn_https_layered,
            'status': update_status
        }

        insert_id = await waf_task_db.update_one(
            search_sql, {"$set": update_task_doc})
        if insert_id:
            return_code = 0
    except Exception:
        logger.info(traceback.format_exc())
        return_code = 1

    res = {
        'return_code': return_code
    }

    return json(res)


