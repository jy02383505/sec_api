#!/usr/bin/env python
import sys
from sanic import Blueprint
from sanic.response import html, text
from sanic.log import logger
from jinja2 import Environment, PackageLoader, select_autoescape
import asyncio
from config import QSURL, QS_TOKEN
from urllib import parse
import aiohttp
import time
import json
from datetime import datetime
from copy import deepcopy
import traceback
import re
from OpenSSL import crypto


waf_bp = Blueprint('waf', url_prefix='waf')

# 开启异步特性  要求3.6+
# enable_async = sys.version_info >= (3, 6)

# jinjia2 config
# env = Environment(
#     loader=PackageLoader('views.sec', '../templates'),
#     autoescape=select_autoescape(['html', 'xml', 'tpl']),
#     enable_async=enable_async)


# async def template(tpl, **kwargs):
#     template = env.get_template(tpl)
#     rendered_template = await template.render_async(**kwargs)
#     return html(rendered_template)


# @waf_bp.route("/")
# async def index(request):
#     # get_service(loop)
#     return await template('index.html')


# class WafReceiver:

#     def __init__(self):
#         cols = await getCollections(request)

#     @waf_bp.get('/testLoop')
#     async def testLoop(self, request):
#         print(f'{self.__dict__}')
#         print(f'{request.__dict__}')


async def getCollections(M, channel):
    protocol, record, domain = parseProtocolRecordDomain(channel)
    theD = getTheD(channel)
    wafInfo = await M.domain.find_one({'protocol': protocol, 'domain': theD})
    if not wafInfo:
        raise Exception(json.dumps({'return_code': -1, 'message': f'collection(domain) has nothing and the channelIs: {channel}'}))
    collectionNames = wafInfo.get('waf')
    #---error
    if not collectionNames:
        return
    return collectionNames


async def getToken(M, channel):
    protocol, record, domain = parseProtocolRecordDomain(channel)
    logger.info(f'getToken channel: {channel}|| protocol: {protocol}|| record: {record}|| domain: {domain}')
    theD = getTheD(channel)
    wafInfo = await M.domain.find_one({'protocol': protocol, 'domain': theD})
    user_id = wafInfo.get('user_id')
    u_p_info = await M.user_profile.find_one({'user_id': user_id})
    qingsongToken = u_p_info.get('qingsong_security_waf')
    return qingsongToken


@waf_bp.route('/forWrk', methods=['POST'])
async def forWrk(request):
    st = time.time()
    R = request.app.R
    num = request.json.get('num')
    num = randint(5, num)
    logger.info(f'forWrk[showInfo] num(type: {type(num)}): {num}')

    theKey = 'forWrk_%s' % num
    for i in range(num):
        await R.incr(theKey)
    rExpire = await R.expire(theKey, 600)
    val = await R.get(theKey)
    logger.info(f'forWrk[operations finished and take {time.time()-st}s.] rExpire: {rExpire}|| val: {val}')

    return text('ok')


def doubleProtocolData(userdata):
    userdata_theother = deepcopy(userdata)
    if userdata.get('protocol') == 'http':
        userdata_theother['protocol'] = 'https'
        userdata_theother['channel'] = f"{userdata_theother['protocol']}://{userdata.get('record')}.{userdata.get('domain')}"
    else:
        userdata_theother['protocol'] = 'http'
        userdata_theother['channel'] = f"{userdata_theother['protocol']}://{userdata.get('record')}.{userdata.get('domain')}"
    userdata_theother.pop('_id')
    logger.info(f'doubleProtocolData userdata_theother: {userdata_theother}')
    return userdata_theother


@waf_bp.route('/waf_rest', methods=['POST'])
async def wafRest(request):
    M = request.app.M
    data = json.loads(request.json)
    product = data.get('product')
    channel_list = data.get('channels')
    if not channel_list:
        return text(json.dumps({'msg': 'channel_list has nothing.', 'return_code': -1}))

    logger.info(f'wafRest channel_list: {channel_list}')
    result = [await waf_rest(request, product, channel) for channel in channel_list]
    logger.info(f'wafRest result: {result}')
    return text(json.dumps({'msg': 'ok.', 'return_code': 0}))


@waf_bp.post('/default_rule_list')
async def waf_default_rule_list(request):
    M = request.app.M
    waf_default_data = request.json
    channel = waf_default_data.get('channel')
    protocol, record, domain = parseProtocolRecordDomain(channel)

    response_dict = {}
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')
            if channel is None:
                return text(f'waf_default_rule_list[product({product}) data posted error.] waf_default_data: {waf_default_data}')
            request.app.QS.channel = channel
            rDefaultWafRuleList = await request.app.QS.default_waf_rule_list(domain_id, record_name)
            logger.info(f'waf_default_rule_list product: {product}|| waf_default_data: {waf_default_data}|| rDefaultWafRuleList: {rDefaultWafRuleList}')
            response_dict[product] = rDefaultWafRuleList
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/set_defense_mode')
async def set_defense_mode(request):
    M = request.app.M
    channel = request.json.get('channel')
    switch = request.json.get('switch')
    default = request.json.get('default')
    if channel is None or switch is None or default is None:
        return text(f'set_defense_mode[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')
            request.app.QS.channel = channel
            rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record_name, default, switch)

            mode_map = {1: 'default_waf_mode', 0: 'self_waf_mode'}
            # rUpdate = await M[col].update_many({'domain_id': domain_id, 'record': record_name}, {'$set': {mode_map[int(default)]: switch}})
            # logger.info(f'set_defense_mode product: {product}|| data: {request.json}|| rSetRecordWafDefense: {rSetRecordWafDefense}|| rUpdate: ({rUpdate.modified_count}/{rUpdate.matched_count})')
            logger.info(f'set_defense_mode product: {product}|| data: {request.json}|| rSetRecordWafDefense: {rSetRecordWafDefense}')
            response_dict[product] = rSetRecordWafDefense
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/self_rule_list')
async def self_rule_list(request):
    M = request.app.M
    channel = request.json.get('channel')
    protocol, record, domain = parseProtocolRecordDomain(channel)

    response_dict = {}
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')
            if channel is None:
                return text(f'self_rule_list[product({product}) data posted error.] waf_default_data: {waf_default_data}')
            request.app.QS.channel = channel
            rWafRuleList = await request.app.QS.waf_rule_list(domain_id, record_name)
            logger.info(f'self_rule_list product: {product}|| data: {request.json}|| rWafRuleList: {rWafRuleList}')
            response_dict[product] = rWafRuleList
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/enable_default_rule')
async def enable_default_rule(request):
    M = request.app.M
    channel = request.json.get('channel')
    rule_id = request.json.get('rule_id')
    enable = request.json.get('enable')
    if rule_id is None or enable is None or channel is None:
        logger.error(f'enable_default_rule[data posted error.] data: {request.json}')
        return text(f'enable_default_rule[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')

            request.app.QS.channel = channel
            rSetDefaultWafRuleEnable = await request.app.QS.set_default_waf_rule_enable(domain_id, record_name, rule_id, enable)
            logger.info(f'enable_default_rule product: {product}|| data: {request.json}|| rSetDefaultWafRuleEnable: {rSetDefaultWafRuleEnable}')
            response_dict[product] = rSetDefaultWafRuleEnable
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/enable_self_rule')
async def enable_self_rule(request):
    M = request.app.M
    rule_id = request.json.get('rule_id')
    enable = request.json.get('enable')
    channel = request.json.get('channel')
    if rule_id is None or enable is None or channel is None:
        logger.error(f'enable_self_rule[data posted error.] data: {request.json}')
        return text(f'enable_self_rule[data posted error.] data: {request.json}')

    response_dict = {}
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            request.app.QS.channel = channel
            rSetWafRuleEnable = await request.app.QS.set_waf_rule_enable(rule_id, enable)
            logger.info(f'enable_self_rule product: {product}|| data: {request.json}|| rSetWafRuleEnable: {rSetWafRuleEnable}')
            response_dict[product] = rSetWafRuleEnable
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/reset_default_waf')
async def reset_default_waf(request):
    M = request.app.M
    channel = request.json.get('channel')
    enable = request.json.get('enable')
    if channel is None or enable is None:
        logger.error(f'reset_default_waf[data posted error.] data: {request.json}')
        return text(f'reset_default_waf[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try: 
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')

            request.app.QS.channel = channel
            rSetDefaultWaf = await request.app.QS.set_default_waf(domain_id, record_name, enable)
            logger.info(f'reset_default_waf product: {product}|| data: {request.json}|| rSetDefaultWaf: {rSetDefaultWaf}')
            response_dict[product] = rSetDefaultWaf

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/log_list')
async def log_list(request):
    M = request.app.M
    channel = request.json.get('channel')
    other_fields = deepcopy(request.json)
    other_fields.pop('channel')
    if channel is None:
        logger.error(f'log_list[data posted error.] data: {request.json}')
        return text(f'log_list[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')

            request.app.QS.channel = channel
            rWafReport = await request.app.QS.waf_report(domain_id, record_name, other_fields)
            logger.info(f'log_list data: {request.json}|| product: {product}|| rWafReport: {rWafReport}')
            response_dict[product] = rWafReport

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/log_detail')
async def log_detail(request):
    M = request.app.M
    channel = request.json.get('channel')
    log_id = request.json.get('log_id')
    log_time = request.json.get('log_time')
    if channel is None or log_id is None or log_time is None:
        logger.error(f'log_detail[data posted error.] data: {request.json}')
        return text(f'log_detail[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')

            request.app.QS.channel = channel
            rWafLogDetail = await request.app.QS.waf_log_detail(domain_id, log_id, log_time)
            logger.info(f'log_detail data: product: {product}|| {request.json}|| rWafLogDetail: {rWafLogDetail}')
            response_dict[product] = rWafLogDetail
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


@waf_bp.post('/statistics')
async def statistics(request):
    M = request.app.M
    channel = request.json.get('channel')
    start_day = request.json.get('start_day')
    end_day = request.json.get('end_day')

    if channel is None:
        logger.error(f'statistics[data posted error.] data: {request.json}')
        return text(f'statistics[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record = wafInfo.get('record')

            request.app.QS.channel = channel
            rWafDefenseAggregate = await request.app.QS.waf_defense_aggregate(domain_id, record, start_day, end_day)
            logger.info(f'statistics product: {product}|| data: {request.json}|| rWafDefenseAggregate: {rWafDefenseAggregate}')
            response_dict[product] = rWafDefenseAggregate
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


def getTheD(channel):
    protocol, record, domain = parseProtocolRecordDomain(channel)
    return f'{record}.{domain}' if record else domain


@waf_bp.post('/current_modes')
async def current_modes(request):
    M = request.app.M
    channel = request.json.get('channel')

    if channel is None:
        logger.error(f'current_modes[data posted error.] data: {request.json}')
        return text(f'current_modes[data posted error.] data: {request.json}')

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col = f'{product}_waf_info'

            wafInfo = await M[col].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')

            recordInfo, return_code = await check_record(request, domain_id, channel)

            request.app.QS.channel = channel
            rRecordWaf = await request.app.QS.record_waf(domain_id, record_name)
            if rRecordWaf['return_code'] == 0:
                rRecordWaf['default_waf_mode'] = rRecordWaf['data']['default_waf']
                rRecordWaf['self_waf_mode'] = rRecordWaf['data']['waf']
                rRecordWaf['ssl_status'] = recordInfo['info']['ssl_status']
            logger.info(f'current_modes product: {product}|| data: {request.json}|| rRecordWaf: {rRecordWaf}')
            response_dict[product] = rRecordWaf
        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


async def check_domain(request, channel):
    '''
    {'status': 2, 'domain': 'chinacache.com', 'type': 1, 'id': '393838', 'service': {'service_id': 283, 'left_days': 340, 'server_name': '高级版WAF防御套餐', 'defense_days': 25}}
    '''
    request.app.QS.channel = channel
    rAllDomain = await request.app.QS.all_domain()
    return_code = rAllDomain.get('return_code')
    dInfo = {}
    if return_code == 0:
        protocol, record, domain = parseProtocolRecordDomain(channel)
        domain_list = rAllDomain['data']['domain_list']
        for domainInfo in domain_list:
            if domainInfo.get('domain') == domain:
                dInfo = domainInfo
                break
        logger.debug(f'check_domain channel: {channel}|| dInfo: {dInfo}|| rAllDomain: {rAllDomain}')

    return dInfo, return_code


@waf_bp.post('/check_status')
async def check_status(request):
    '''
    rStatus
        0: for bind with open waf service
        1: for bind with closed waf service
        2: for create
        3: waiting for audit
        4: audit not through
    '''
    M = request.app.M
    channel = request.json.get('channel')
    provider = request.json.get('provider')

    if channel is None or provider is None:
        logger.error(f'check_status[data posted error.] data: {request.json}')
        return_dict = {'return_code': -2, 'message': f'data posted error.{request.json}'}
        return text(json.dumps({provider: return_dict}))

    protocol, record, domain = parseProtocolRecordDomain(channel)
    if record == '':
        logger.error(f'check_status[record_name empty.] data: {request.json}')
        return_dict = {'return_code': -2, 'message': '不能创建waf'}
        return text(json.dumps({provider: return_dict}))

    response_dict = {}
    userdata = {}

    try:
        # rStatus = -1
        #---check the domain.
        domainInfo, return_code_domain = await check_domain(request, channel)
        if not domainInfo:
            logger.warn(f'check_status[domainNotExisted.] channel: {channel}|| domainInfo: {domainInfo}')
            response_dict.setdefault(provider, {}).update({'status': 2, 'return_code': return_code_domain})
            return text(json.dumps(response_dict))
        logger.info(f'check_status[check_domainDone.] channel: {channel}|| domainInfo: {domainInfo}')

        status = domainInfo.get('status')
        if status == -1:
            logger.info(f'check_status[auditing.] channel: {channel}|| domainInfo: {domainInfo}')
            response_dict.setdefault(provider, {}).update({'status': 3, 'return_code': return_code_domain})
            return text(json.dumps(response_dict))

        if status == -2:
            logger.info(f'check_status[audit not through.] channel: {channel}|| domainInfo: {domainInfo}')
            response_dict.setdefault(provider, {}).update({'status': 4, 'return_code': return_code_domain})
            return text(json.dumps(response_dict))

        domain_id = domainInfo.get('id')

        userdata.update({'domain': domain, 'record': record, 'domain_status': status, 'domain_id': domain_id, 'created_time': datetime.now()})

        col_info = f'{provider}_waf_info'
        rIi = await M[col_info].index_information()
        logger.debug(f'check_status channel: {channel}|| rIi: {rIi}')
        if '_id_' in rIi and len(rIi) < 2:
            await M[col_info].create_index([('domain', 1), ('record', 1)], unique=True, background=True)
            await M[col_info].create_index('domain_id', background=True)
            await M[col_info].create_index('domain_status', background=True)
            logger.info(f'check_status[create_index Done.] channel: {channel}')

        wafInfo = await M[col_info].find_one({'domain': domain, 'record': record})
        if not wafInfo:
            rInsert = await M[col_info].insert_one(userdata)
            logger.info(f'check_status[insert Done.] rInsert_id: {rInsert.inserted_id}|| userdata: {userdata}|| domainInfo: {domainInfo}')
            wafInfo = await M[col_info].find_one({'domain': domain, 'record': record})

        #---check the record.
        result, return_code = await check_record(request, domain_id, channel)
        recordInfo = result['info']
        '''
        {'code': 300, 'msg': 'both domain and record exist.', 'info': {'name': 'itest.chinacache.com', 'ip': '223.202.203.31', 'checkin': 0, 'port': '80', 'cname': 'd49dd336da49ac83.7cname.com', 'ssl_port': '', 'ssl_status': 0, 'cert_id': '', 'view': '默认', 'id': '14128Q3754609439', 'md5': 'd49dd336da49ac83'}}
        ---
        {'code': 302, 'msg': '[III]domain does not exist.', 'info': {'action': 'record_site_list', 'message': '找不到域名', 'return_code': 1}}
        '''
        if return_code == 0:
            if recordInfo.get('name') == getTheD(channel):
                logger.info(f'check_status[recordExisted.] recordInfo: {recordInfo}')
                response_dict.setdefault(provider, {}).update({'status': 0 if status == 2 else 1, 'return_code': return_code})

                #---save record_id into mongo
                if not wafInfo.get('record_id'):
                    record_id = recordInfo['id']
                    cert_id = recordInfo['cert_id']
                    record_new = {'record_id': record_id, 'cert_id': cert_id}
                    rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': record_new})
                    logger.info(f'check_status channel: {channel}|| record_id: {record_id}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')
                return text(json.dumps(response_dict))

        logger.info(f'check_status[recordNotExisted.] recordInfo: {recordInfo}')
        response_dict.setdefault(provider, {}).update({'status': 2, 'return_code': 0})
        return text(json.dumps(response_dict))

    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict = {'return_code': -1, 'message': e}
        return text(json.dumps({provider: return_dict}))


async def check_record(request, domain_id, channel, cert_list=False):
    '''
    theD = f'{record}.{domain}'
    '''
    M = request.app.M
    theD = getTheD(channel)
    request.app.QS.channel = channel
    rRecordList = await request.app.QS.record_list(domain_id)
    # rRecordSiteList = await request.app.QS.record_site_list(domain_id) # use when cert_list == True
    rInfo = {'code': -1, 'msg': 'record does not exist.', 'info': {}}
    return_code_ip = rRecordList.get('return_code')
    return_code = return_code_ip
    skip = False
    if return_code_ip == 0:
        rcd_ip_list = rRecordList['data']['record_list']
        logger.debug(f'check_record rcd_ip_list: {rcd_ip_list}')
        for rcdInfo_ip in rcd_ip_list:
            if rcdInfo_ip.get('name') == theD:
                logger.debug(f'check_record rcdInfo_ip: {rcdInfo_ip}')
                rInfo = {'code': 300, 'msg': 'both domain and record exist.', 'info': rcdInfo_ip}
                skip = True
                break
    else:
        rInfo = {'code': 302, 'msg': '[III]domain does not exist.', 'info': rRecordList}

    # ---already found the record above, skip these steps.
    if not skip:
        rRecordSiteList = await request.app.QS.record_site_list(domain_id)
        return_code_site = rRecordSiteList.get('return_code')
        if return_code_site == 0:
            rcd_site_list = rRecordSiteList['data']['record_list']
            logger.debug(f'check_record rcd_site_list: {rcd_site_list}')
            for rcdInfo_site in rcd_site_list:
                if rcdInfo_site.get('name') == theD:
                    logger.debug(f'check_record rcdInfo_site: {rcdInfo_site}')
                    rInfo = {'code': 300, 'msg': 'both domain and record exist.', 'info': rcdInfo_site}
                    break
        else:
            rInfo = {'code': 302, 'msg': '[III]domain does not exist.', 'info': rRecordSiteList}
        return_code = return_code_ip if return_code_ip != 0 else return_code_site

    logger.debug(f'check_record rInfo: {rInfo}')

    if cert_list:
        record_list = rcd_ip_list + rcd_site_list
        cert_id_list = [r['cert_id'] for r in record_list if r.get('cert_id')]
        logger.debug(f'check_record cert_id_list: {cert_id_list}')
        return cert_id_list

    return rInfo, return_code


async def sourceIP_or_sourceSite(request, recordInfo, return_code, channel):
    result = {}

    result['source_is_ip'] = True if recordInfo.get('ip') else False
    result['source_addr'] = recordInfo.get('ip') if result['source_is_ip'] else recordInfo.get('source_site')
    result['port'] = recordInfo.get('port')
    result['ssl_port'] = recordInfo.get('ssl_port')
    result['ssl_status'] = recordInfo.get('ssl_status')
    result['cert_id'] = recordInfo.get('cert_id')

    result['return_code'] = return_code

    result['cert_name'] = ''
    if result.get('cert_id'):
        cert_info = await get_cert_info(request, {'id': result['cert_id']}, channel)
        if cert_info is not None:
            result['cert_name'] = cert_info.get('name')

    logger.info(f'sourceIP_or_sourceSite result: {result}|| recordInfo: {recordInfo}')
    return result


async def get_cert_info(request, search_dict, channel, total_list=False):
    '''
    keys of search_dict: one in [id, name]
    '''
    request.app.QS.channel = channel
    rCertList = await request.app.QS.cert_list()
    logger.debug(f'get_cert_info rCertList: {rCertList}')
    if not search_dict:
        return
    if rCertList['return_code'] == 0:
        cert_list = rCertList['data']['cert_list']
        if total_list:
            cert_id_list = [c['id'] for c in cert_list if c.get('id')]
            logger.debug(f'get_cert_info cert_id_list: {cert_id_list}')
            return cert_id_list
        for certInfo in cert_list:
            for k, v in search_dict.items():
                # logger.debug(f'get_cert_info certInfo: {certInfo}|| k: {k}|| v: {v}')
                if certInfo.get(k) == v:
                    logger.info(f'get_cert_info search_dict: {search_dict}|| certInfo: {certInfo}')
                    return certInfo
    logger.error(f'get_cert_info[findNothing].rCertList: {rCertList}')
    return


# @waf_bp.post('/activate')
async def activate(request, channel):
    M = request.app.M
    # channel = request.json.get('channel')
    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}

    if channel is None:
        logger.error(f'activate[data posted error.] data: {request.json}')
        return_dict[provider]['message'] = f'activate[data posted error.] data: {request.json}'
        return text(json.dumps(return_dict))

    response_dict = {}
    theD = getTheD(channel)
    protocol, record, domain = parseProtocolRecordDomain(channel)
    logger.info(f'activate data: {request.json}|| theD: {theD}')
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col_info = f'{product}_waf_info'
            col_task = f'{product}_waf_task'

            wafInfo = await M[col_info].find_one({'domain': domain, 'record': record})
            logger.info(f'activate channel: {channel}|| wafInfo({type(wafInfo)}): {wafInfo}')
            domain_id = wafInfo.get('domain_id')

            #---before set_record_defense, check domain_waf to query the value of switch.
            request.app.QS.channel = channel
            rGetDomainInfo = await request.app.QS.get_domain_info(domain_id=domain_id)
            if rGetDomainInfo.get('return_code') != 0:
                logger.error(f'activate[get_domain_info error.] rGetDomainInfo: {rGetDomainInfo}')
                response_dict.setdefault(product, {}).update(rGetDomainInfo)
                return text(json.dumps(response_dict))
            logger.info(f'activate[get_domain_info done.] rGetDomainInfo: {rGetDomainInfo}')

            if rGetDomainInfo['data']['status'] != 0:
                logger.error(f'activate[domainAlreadyActivatedBefore.] rGetDomainInfo: {rGetDomainInfo}')
                response_dict.setdefault(product, {}).update(rGetDomainInfo)

                #--- domain already existed but record not.
                rDomainWaf = await request.app.QS.domain_waf(domain_id=domain_id)
                if rDomainWaf.get('return_code') != 0:
                    logger.error(f'activate[domain_waf error.] rDomainWaf: {rDomainWaf}')
                    response_dict.setdefault(product, {}).update(rDomainWaf)
                    return text(json.dumps(response_dict))
                logger.info(f'activate[domain_waf done.] channel: {channel}|| domain_id: {domain_id}|| rDomainWaf: {rDomainWaf}')
                theSwitch = rDomainWaf['data']['switch']

                rSetRecordDefense = await request.app.QS.set_record_defense(domain_id=domain_id, record_name=record, switch=theSwitch)
                if rSetRecordDefense.get('return_code') != 0:
                    logger.error(f'activate[set_record_defense error.] rSetRecordDefense: {rSetRecordDefense}')
                    response_dict.setdefault(product, {}).update(rSetRecordDefense)
                    return text(json.dumps(response_dict))
                logger.info(f'activate[set_record_defense done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| switch: {theSwitch}')

                return text(json.dumps(response_dict))

            rDomainWaf = await request.app.QS.domain_waf(domain_id=domain_id)
            if rDomainWaf.get('return_code') != 0:
                logger.error(f'activate[domain_waf error.] rDomainWaf: {rDomainWaf}')
                response_dict.setdefault(product, {}).update(rDomainWaf)
                return text(json.dumps(response_dict))
            logger.info(f'activate[domain_waf done.] channel: {channel}|| domain_id: {domain_id}|| rDomainWaf: {rDomainWaf}')
            theSwitch = rDomainWaf['data']['switch']

            domainInfo, return_code_domain = await check_domain(request, channel)
            if not domainInfo['service'] and domainInfo.get('status') == 0:
                #---1.third_buy_waf + 2.service_bind + 3.all_domain
                rThirdBuyWaf = await request.app.QS.third_buy_waf()
                return_code = rThirdBuyWaf.get('return_code')
                if rThirdBuyWaf.get('return_code') != 0:
                    response_dict[product] = rThirdBuyWaf
                    logger.error(f'activate[third_buy_waf error.] error: {rThirdBuyWaf}|| domainInfo: {domainInfo}')
                    return text(json.dumps(response_dict))
                service_id = rThirdBuyWaf['data']['id'][0]
                logger.info(f'activate[third_buy_waf Done.] channel: {channel}|| service_id: {service_id}|| domainInfo: {domainInfo}')

                rServiceBind = await request.app.QS.service_bind(domain_id, service_id)
                if rServiceBind.get('return_code') != 0:
                    response_dict[product] = rServiceBind
                    logger.error(f'activate[service_bind error.] error: {rServiceBind}|| domainInfo: {domainInfo}')
                    return text(json.dumps(response_dict))
                logger.info(f'activate[service_bind Done.] channel: {channel}|| service_id: {service_id}|| domain_id: {domain_id}|| domainInfo: {domainInfo}')

                #---this query is for update domain_status
                rGetDomainInfo = await request.app.QS.get_domain_info(domain_id)
                if rGetDomainInfo['return_code'] != 0:
                    response_dict[product] = rGetDomainInfo
                    logger.error(f'activate[get_domain_info error.] channel: {channel}|| error: {rGetDomainInfo}')
                    return text(json.dumps(response_dict))
                domain_status_new = rGetDomainInfo['data']['status']
            else:
                logger.warn(f'activate[BindingSkipped.] channel: {channel}|| domainInfo: {domainInfo}')

            #---update domain_status
            if domainInfo.get('status') != domain_status_new:
                rUpdate = await M.col_info.update_one({'domain': domain, 'record': record}, {'$set': {'domain_status': domain_status_new}})
                logger.info(f'activate[updateDomainStatusDone.] channel: {channel}|| domain_status: {domainInfo.get("status")}|| domain_status_new: {domain_status_new}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')

            #---bind successfully but leak the operation of set_record_defense.
            '''
            Hobart: 
                3 注意！！！如果API对域名操作WAF服务绑定后, API中有个 [站点记录防御服务总开关] 是默认关闭的, 该开关在极光平台是没有的。
                域名下站点进行操作更新后，则配置是下发不了，实际防御服务会关闭的。API绑定WAF服务后，对站点必须调用 <配置记录防御服务总开关> 接口开启。
            '''
            rSetRecordDefense = await request.app.QS.set_record_defense(domain_id=domain_id, record_name=record, switch=theSwitch)
            if rSetRecordDefense.get('return_code') != 0:
                logger.error(f'activate[set_record_defense error.] rSetRecordDefense: {rSetRecordDefense}')
                response_dict.setdefault(product, {}).update(rSetRecordDefense)
                return text(json.dumps(response_dict))
            logger.info(f'activate[set_record_defense done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| switch: {theSwitch}')

            response_dict.setdefault(product, {}).update({'return_code': rSetRecordDefense['return_code'], 'msg': 'apiBindingFinished.', 'rDomainWaf': rDomainWaf})
            logger.info(f'activate[Finished.] channel: {channel}|| response_dict: {response_dict}')

        return text(json.dumps(response_dict))

    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict[provider]['message'] = e
        return text(json.dumps(return_dict))


@waf_bp.post('/show_info')
async def show_info(request):
    M = request.app.M
    channel = request.json.get('channel')

    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}

    if channel is None:
        logger.error(f'show_info[data posted error.] data: {request.json}')
        return_dict[provider]['message'] = f'show_info[data posted error.] data: {request.json}'
        return text(json.dumps(return_dict))

    response_dict = {}
    theD = getTheD(channel)
    protocol, record, domain = parseProtocolRecordDomain(channel)
    logger.info(f'show_info data: {request.json}|| theD: {theD}')
    try:
        product_list = await getCollections(M, channel)
        if product_list is None:
            logger.error(f'show_info[product_list is None.] channel: {channel}|| data: {request.json}')
            return text(json.dumps(return_dict))

        for product in product_list:
            col_info = f'{product}_waf_info'
            col_task = f'{product}_waf_task'

            wafInfo = await M[col_info].find_one({'domain': domain, 'record': record})
            logger.info(f'show_info channel: {channel}|| wafInfo({type(wafInfo)}): {wafInfo}')
            domain_id = wafInfo.get('domain_id')
            record_name = wafInfo.get('record')

            #---base info
            wafTask = await M[col_task].find_one({'domain': theD})
            if wafTask.get('_id'):
                wafTask.pop('_id')
            response_dict.setdefault(product, {}).update(wafTask)

            #---waf back to the source
            recordInfo, return_code = await check_record(request, domain_id, channel)
            logger.info(f'show_info channel: {channel}|| recordInfo: {recordInfo}')
            srcInfo = await sourceIP_or_sourceSite(request, recordInfo['info'], return_code, channel)
            response_dict[product].update(srcInfo)

            #---get_current_modes
            request.app.QS.channel = channel
            rRecordWaf = await request.app.QS.record_waf(domain_id, record_name)
            if rRecordWaf['return_code'] == 0:
                response_dict[product]['default_waf_mode'] = rRecordWaf['data']['default_waf']
                response_dict[product]['self_waf_mode'] = rRecordWaf['data']['waf']

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict[provider]['message'] = e
        return text(json.dumps(return_dict))


@waf_bp.post('/record_defense')
async def record_defense(request):
    M = request.app.M
    channel = request.json.get('channel')
    switch = request.json.get('switch')
    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}

    if channel is None or switch is None:
        logger.error(f'record_defense[data posted error.] data: {request.json}')
        return_dict[provider]['message'] = f'record_defense[data posted error.] data: {request.json}'
        return text(json.dumps(return_dict))

    response_dict = {}
    product, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col_info = f'{product}_waf_info'

            wafInfo = await M[col_info].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')

            await change_record_waf_switch(request, channel, domain_id, record, switch, product, response_dict)

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict[provider]['message'] = e
        return text(json.dumps(return_dict))

async def change_record_waf_switch(request, channel, domain_id, record, switch, product, response_dict):
    M = request.app.M
    request.app.QS.channel = channel
    rSetRecordDefense = await request.app.QS.set_record_defense(domain_id, record, switch)
    logger.info(f'change_record_waf_switch product: {product}|| data: {request.json}|| rSetRecordDefense: {rSetRecordDefense}')
    response_dict[product] = rSetRecordDefense

    #---update data in mongo
    if rSetRecordDefense.get('return_code') == 0:
        col_task = f'{product}_waf_task'
        theD = getTheD(channel)
        s_code = 2 if switch == 1 else 0
        rUpdateOne = await M[col_task].update_one({'domain': theD}, {'$set': {'status': s_code}})
        logger.info(f'change_record_waf_switch[update status({s_code}) in {col_task}.] rUpdateOne: {rUpdateOne.modified_count}/{rUpdateOne.matched_count}|| channel: {channel}')


async def update_collection_info(request, col, channel, new_dict):
    new_values = {}
    for k, v in new_dict.items():
        if v:
            new_values[k] = v
    theD = getTheD(channel)
    M = request.app.M
    logger.debug(f'update_collection_info[after pop.] channel: {channel}|| new_values: {new_values}')
    rUpdate = await M[col].update_one({'domain': theD}, {'$set': new_values})
    return f'{rUpdate.modified_count}/{rUpdate.matched_count}'

@waf_bp.post('/modify_info')
async def modify_info(request):
    '''
        domain: 域名 -> channel
        access_point: 接入点
        access_point_cname: 接入点对应cname
        access_type: waf接入方式 目前是 2
        src_type: 1 ip回源 & 2 域名回源
        src_address: 回源值 域名回源就是域名,ip回源就是ip
        src_port: 回源端口
        src_host: 回源host
        ssl_status: 是否启用https
        cert_name: 证书名称 -> cert_id
        default_waf_mode: 默认规则防御模式
        self_waf_mode: 自定义规则防御模式
    '''
    M = request.app.M
    data = request.json
    channel = data.get('channel')

    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}

    logger.info(f'modify_info data: {data}')
    if not channel or (len(data) < 2):
        logger.error(f'modify_info[data posted error.] data: {data}')
        return_dict[provider]['message'] = f'modify_info[data posted error.] data: {data}'
        return text(json.dumps(return_dict))

    response_dict = {provider: {'return_code': -1, 'message': '...'}}
    product, record, domain = parseProtocolRecordDomain(channel)
    try:
        product_list = await getCollections(M, channel)
        for product in product_list:
            col_info = f'{product}_waf_info'
            col_task = f'{product}_waf_task'

            wafInfo = await M[col_info].find_one({'record': record, 'domain': domain})
            domain_id = wafInfo.get('domain_id')
            record_id = wafInfo.get('record_id')
            # cert_id = wafInfo.get('cert_id')

            if int(data.get('access_type', -1)) in [1, 2]:
                if data.get('access_point') or data.get('access_point_cname'):
                    values = {}
                    values['access_type'] = data.get('access_type')
                    values['access_point'] = data.get('access_point')
                    values['access_point_cname'] = data.get('access_point_cname')
                    rUpdate = await update_collection_info(request, col_task, channel, values)
                    logger.info(f'modify_info[update new data.] channel: {channel}|| rUpdate: {rUpdate}|| values: {values}')
                    response_dict.setdefault(product, {}).update({'access_*': rUpdate, 'return_code': 0})

            default_waf_mode = int(data.get('default_waf_mode', -1))
            if default_waf_mode in [0, 1, 2, 3]:
                #---default: 1
                request.app.QS.channel = channel
                rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record, default=1, switch=default_waf_mode)
                logger.info(f'modify_info channel: {channel}|| rSetRecordWafDefense: {rSetRecordWafDefense}')
                response_dict.setdefault(product, {}).update({'default_waf_mode': rSetRecordWafDefense, 'return_code': rSetRecordWafDefense.get('return_code')})
            # else:
            #     logger.error(f'modify_info[default_waf_mode must be in [0-1].] channel: {channel}|| default_waf_mode: {default_waf_mode}')

            self_waf_mode = int(data.get('self_waf_mode', -1))
            if self_waf_mode in [0, 1]:
                #---default: 0
                request.app.QS.channel = channel
                rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record, default=0, switch=self_waf_mode)
                logger.info(f'modify_info channel: {channel}|| rSetRecordWafDefense: {rSetRecordWafDefense}')
                response_dict.setdefault(product, {}).update({'self_waf_mode': rSetRecordWafDefense, 'return_code': rSetRecordWafDefense.get('return_code')})
            # else:
            #     logger.error(f'modify_info[self_waf_mode must be in [0-3].] channel: {channel}|| default_waf_mode: {self_waf_mode}')

            ssl_status = int(data.get('ssl_status', -1))
            if ssl_status in [0, 1]:
                cert_id = data.get('cert_id')
                if ssl_status == 1 and not cert_id:
                    logger.error(f'modify_info[missed cert_id.] data: {data}')
                    return_dict[provider]['message'] = f'modify_info[missed cert_id.] data: {data}'
                    return text(json.dumps(return_dict))

                #---find the eld cert_id
                if ssl_status == 1:
                    recordInfo, return_code = await check_record(request, domain_id, channel)
                    recordInfo = recordInfo.get('info')
                    c_id_eld = recordInfo.get('cert_id')

                    request.app.QS.channel = channel
                    rSetHttpsPort = await request.app.QS.set_https_port(record_id)
                    if rSetHttpsPort.get('return_code') != 0:
                        logger.error(f'modify_info[set_https_port error.] rSetHttpsPort: {rSetHttpsPort}')
                        response_dict.setdefault(product, {}).update(rSetHttpsPort)
                        return text(json.dumps(response_dict))

                    logger.info(f'modify_info channel: {channel}|| cert_id: {cert_id}|| c_id_eld: {c_id_eld}')

                    rSetHttpsRecord = await request.app.QS.set_https_record(domain_id, record, ssl_status, cert_id)
                    #---delete the eld cert_id
                    # if ssl_status == 1:
                    if c_id_eld:
                        if rSetHttpsRecord['return_code'] == 0:
                            if c_id_eld != cert_id:
                                rDeleteCert = await request.app.QS.delete_cert(c_id_eld)
                                logger.info(f'modify_info channel: {channel}|| rDeleteCert: {rDeleteCert}')
                    logger.info(f'modify_info channel: {channel}|| rSetHttpsRecord: {rSetHttpsRecord}')
                    response_dict.setdefault(product, {}).update({'ssl_status': rSetHttpsRecord, 'return_code': rSetHttpsRecord.get('return_code')})

            src_type = int(data.get('src_type', 0))
            src_address = data.get('src_address')
            src_port = int(data.get('src_port', 0))
            if src_type and (src_address or src_port):
                src_dict = {}
                src_type_d = {1: 'ip', 2: 'source_site'}
                src_dict[src_type_d[src_type]] = data.get('src_address')
                src_dict['port'] = src_port
                var_dict = {}
                for k,v in src_dict.items():
                    if v:
                        var_dict[k] = v
                rUpInfo = await update_record_info(request, src_type, channel, record_id, var_dict, domain_id, col_info)
                response_dict.setdefault(product, {}).update({'src_info': rUpInfo, 'return_code': rUpInfo.get('return_code')})

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(e)


async def update_record_info(request, src_type, channel, record_id, var_dict, domain_id, col_info):
    '''
        # int(source_is_ip): 0 or 1
        # src_type: 1 or 2
    '''
    M = request.app.M
    protocol, record, domain = parseProtocolRecordDomain(channel)
    recordInfo, return_code = await check_record(request, domain_id, channel)
    srcInfo = await sourceIP_or_sourceSite(request, recordInfo['info'], return_code, channel)
    source_is_ip = srcInfo.get('source_is_ip')
    src_type = int(src_type)
    if source_is_ip:
        # (same)ip->ip
        if src_type == 1:
            rModifyRecord = await request.app.QS.modify_record(record_id, var_dict)
            logger.info(f'update_record_info[(same)ip->ip.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rModifyRecord: {rModifyRecord}')
            return rModifyRecord
        # (different)ip->site
        else:
            rDeleteRecord = await request.app.QS.delete_record(record_id)
            logger.info(f'update_record_info[(different)ip->site.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rDeleteRecord: {rDeleteRecord}')
            if rDeleteRecord.get('return_code') == 0:
                rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'record_id': ''}})
                logger.info(f'update_record_info[(different)ip->site.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rUpdate[record_id delete done.]: {rUpdate.modified_count}/{rUpdate.matched_count}')
                rAddRecordSite = await request.app.QS.add_record_site(domain_id, record, var_dict.pop('source_site'), var_dict)
                rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'record_id': rAddRecordSite['data']['record_id']}})
                logger.info(f'update_record_info[(different)ip->site.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rAddRecordSite: {rAddRecordSite}|| rUpdate[record_id update done.]: {rUpdate.modified_count}/{rUpdate.matched_count}')
                return rAddRecordSite
            else:
                logger.error(f'update_record_info[(different)ip->site.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rDeleteRecord: {rDeleteRecord}')

    else:
        # (different)site->ip
        if src_type == 1:
            rDeleteRecordSite = await request.app.QS.delete_record_site(record_id)
            logger.info(f'update_record_info[(different)site->ip.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rDeleteRecordSite: {rDeleteRecordSite}')
            if rDeleteRecordSite.get('return_code') == 0:
                rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'record_id': ''}})
                logger.info(f'update_record_info[(different)site->ip.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rUpdate[record_id update done.]: {rUpdate.modified_count}/{rUpdate.matched_count}')
                rAddRecord = await request.app.QS.add_record(domain_id, record, var_dict.pop('ip'), var_dict)
                rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'record_id': rAddRecord['data']['record_id']}})
                logger.info(f'update_record_info[(different)site->ip.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rAddRecord: {rAddRecord}|| rUpdate[record_id update done.]: {rUpdate.modified_count}/{rUpdate.matched_count}')
                return rAddRecord
            else:
                logger.error(f'update_record_info[(different)site->ip.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rDeleteRecordSite: {rDeleteRecordSite}')
        # (same)site->site
        else:
            rModifyRecordSite = await request.app.QS.modify_record_site(record_id, var_dict.pop('source_site'), var_dict)
            logger.info(f'update_record_info[(same)site->site.] channel: {channel}|| src_type: {src_type}|| record_id: {record_id}|| var_dict: {var_dict}|| rModifyRecordSite: {rModifyRecordSite}')
            return rModifyRecordSite


@waf_bp.post('/cert_up')
async def cert_up(request):
    M = request.app.M
    data = request.json
    channel = data.get('channel')
    name = data.get('name')
    # crt_name = data.get('crt_name')
    cert = data.get('cert')
    # key_name = data.get('key_name')
    key = data.get('key')

    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}
    fields_must = ['channel', 'name', 'cert', 'key']
    for field in fields_must:
        # if eval(field) is None:
        if data.get(field) is None:
            logger.error(f'cert_up[data posted error.] data: {request.json}')
            return_dict[provider]['message'] = f'cert_up[data posted error.] data: {request.json}'
            return text(json.dumps(return_dict))

    try:
        crt_name, key_name = makeCertName(cert)
        logger.info(f'cert_up data: {request.json}|| crt_name: {crt_name}|| key_name: {key_name}')
    except Exception as e:
        logger.error(traceback.format_exc())
        return text(json.dumps({'QINGSONG': {'message': e, 'return_code': -1}}))

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    try:
        # product_list = await getCollections(M, channel)
        # for product in product_list:
        product = 'QINGSONG'
        request.app.QS.channel = channel
        rAddCert = await request.app.QS.add_cert(name, crt_name, cert, key_name, key)
        response_dict[product] = rAddCert
        logger.info(f'cert_up[add_cert done.] data: {request.json}|| rAddCert: {rAddCert}')

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict[provider]['message'] = e
        return text(json.dumps(return_dict))


def makeCertName(cert):
    theCert = parse_cert(cert)
    logger.info(f'makeCertName theCert: {theCert}')
    theCertInfo = parse_validity(theCert[0])
    end_time_str = datetime.strftime(theCertInfo.get("end_time"), "%Y-%m-%d-%H")
    now_str = datetime.strftime(datetime.now(), "%Y-%m-%d-%H-%M-%S")
    return tuple(f'{end_time_str}-{theCertInfo.get("issued_to")}-{now_str}.{suffix}' for suffix in ['crt', 'key'])


def parse_cert(crt):
    '''
    由顶层逐个解析返回　证书对象
    [3级,中级,根]
    '''

    res = []
    detail = re.findall("\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-[\w|\W]+?(?:\-\-\-\-\-END CERTIFICATE\-\-\-\-\-)", crt)
    for x in range(len(detail)):
        crt_obj = crypto.load_certificate(crypto.FILETYPE_PEM, detail[x])
        res.append(crt_obj)
    return res


def parse_validity(cert):
    '''
    证书有效时间戳
    '''
    begin_obj = datetime.strptime(str(cert.get_notBefore(), 'utf-8'), '%Y%m%d%H%M%SZ')
    end_obj = datetime.strptime(str(cert.get_notAfter(), 'utf-8'), '%Y%m%d%H%M%SZ')
    issued_to = cert.get_subject().CN.replace('*', '_')
    cert_time={'begin_time': begin_obj, 'end_time': end_obj, 'issued_to': issued_to}
    return cert_time


# @waf_bp.post('/create')
async def create(request, data, provider='QINGSONG'):
    '''
    post:
        domain: 域名 -> channel
        access_point: 接入点
        access_point_cname: 接入点对应cname
        access_type: waf接入方式 1是“上层>waf>源站”，2是“边缘>waf>上层”
        src_type: 1 ip回源 & 2 域名回源
        src_address: 回源值 域名回源就是域名,ip回源就是ip
        src_port: 回源端口
        src_host: 回源host
        ssl_status: 是否启用https
        cert_name: 证书名称 -> cert_id
        default_waf_mode: 默认规则防御模式
        self_waf_mode: 自定义规则防御模式
    return:
        rStatus, 
    '''
    M = request.app.M
    # data = request.json
    channel = data.get('channel')
    ssl_status = int(data.get('ssl_status', -1))
    fields_must = ['channel', 'access_type', 'access_point', 'access_point_cname', 'src_type', 'src_address', 'src_port', 'ssl_status', 'default_waf_mode', 'self_waf_mode']

    return_dict = {provider: {'return_code': -1, 'message': '...'}}

    for k in fields_must:
        if data.get(k, False) is False:
            logger.error(f'create[data posted error.] data: {data}')
            message = f'create[data posted error.] data: {data}'
            return_dict[provider]['message'] = message
            return text(json.dumps(return_dict))
    if ssl_status == 1:
        if not data.get('cert_id'):
            logger.error(f'create[cert_id missed.] data: {data}')
            message = f'create[cert_id missed.] data: {data}'
            return_dict[provider]['message'] = message
            return text(json.dumps(return_dict))

    response_dict = {}
    protocol, record, domain = parseProtocolRecordDomain(channel)
    theD = getTheD(channel)
    logger.info(f'create data: {data}')

    access_type = data.pop('access_type')
    access_point = data.pop('access_point')
    access_point_cname = data.pop('access_point_cname')
    try:
        # product_list = await getCollections(M, channel)
        # for product in product_list:
        col_info = f'{provider}_waf_info'
        col_task = f'{provider}_waf_task'

        rUpdate = await M[col_task].update_one({'domain': theD}, {'$set': {'access_type': access_type, 'access_point': access_point, 'access_point_cname': access_point_cname}}, upsert=True)
        logger.info(f'create channel: {channel}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}|| upserted_id: {rUpdate.upserted_id}')

        userdata = {}
        userdata['cInfo'] = data
        userdata['domain'] = domain
        userdata['record'] = record
        userdata['created_time'] = datetime.now()

        wafInfo = await M[col_info].find_one({'record': record, 'domain': domain})
        # logger.info(f'create channel: {channel}|| wafInfo: {wafInfo}|| userdata: {userdata}')

        if wafInfo is None:
            rInsert = await M[col_info].insert_one(userdata)
            logger.info(f'create[inserted_id: {rInsert.inserted_id}] channel: {channel}|| userdata: {userdata}')
            wafInfo = await M[col_info].find_one({'record': record, 'domain': domain})

        if not wafInfo.get('cInfo'):
            rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'cInfo': data}})
            logger.info(f'create[updateCInfo.] channel: {channel}|| cInfo: {data}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')

        rIi = await M[col_info].index_information()
        if '_id_' in rIi and len(rIi) < 2:
            await M[col_info].create_index([('domain', 1), ('record', 1)], unique=True, background=True)
            await M[col_info].create_index('domain_id', background=True)
            await M[col_info].create_index('domain_status', background=True)
            logger.info(f'create[create_index done.] channel: {channel}')

        request.app.QS.channel = channel
        rAddDomain = await request.app.QS.add_domain(domain)
        if rAddDomain['return_code'] == 0:
            domain_id = rAddDomain['data']['domain_id']
            domain_status = rAddDomain['data']['status']
            rUpdate = await M[col_info].update_one({'record': record, 'domain': domain}, {'$set': {'domain_id': domain_id, 'domain_status': domain_status}})
            logger.info(f'create[add_domain done.] data: {data}|| rAddDomain: {rAddDomain}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')

            if domain_status == 0:
                # waf_rest...
                logger.info(f'create[going to waf_rest.] channel: {channel}|| data: {data}|| rAddDomain: {rAddDomain}')
                return await waf_rest(request, provider, channel)
            elif domain_status == -1:
                logger.info(f'create[domain waiting to be audited.] data: {data}|| rAddDomain: {rAddDomain}')
                # rStatus = domain_status
                response_dict[provider] = rAddDomain
                return text(json.dumps(response_dict))
            elif domain_status == -2:
                logger.warn(f'create[domain audited failed.] data: {data}|| rAddDomain: {rAddDomain}')
                response_dict[provider] = rAddDomain
                return text(json.dumps(response_dict))

        elif rAddDomain['return_code'] == 1:
            logger.warn(f'create[domain already existed.] data: {data}|| rAddDomain: {rAddDomain}')
            # waf_rest...
            return await waf_rest(request, provider, channel)
        else:
            logger.error(f'create[domain format error.] data: {data}|| rAddDomain: {rAddDomain}')
            response_dict[provider] = rAddDomain

        return text(json.dumps(response_dict))
    except Exception as e:
        logger.error(traceback.format_exc())
        return_dict[provider]['message'] = e
        return text(json.dumps(return_dict))


@waf_bp.post('/tellWhetherBind')
async def tellWhetherBind(request):
    '''
        用于前端区分该记录是绑定or创建
    '''
    M = request.app.M
    data = request.json
    channel = data.get('channel')
    if not channel:
        logger.error(f'tellWhetherBind[dataError.] data: {data}')
        return text(f'tellWhetherBind data: {data}')
    protocol, record, domain = parseProtocolRecordDomain(channel)
    wafInfo = await M['QINGSONG_waf_info'].find_one({'domain': domain, 'record': record})
    if not wafInfo:
        return text(json.dumps(False))
    result = False if wafInfo.get('cInfo') else True
    return text(json.dumps(result))



@waf_bp.post('/delete_record')
async def deleteRecord(request):
    '''
        1.记录级别的删除
        2.需要联动删除的点：domain表中的waf字段、QINGSONG_waf_task表中的整条记录、QINGSONG_waf_info表中的整条记录
    '''
    provider = 'QINGSONG'
    return_dict = {provider: {'return_code': -1, 'message': '...'}}
    M = request.app.M
    data = request.json
    channel = data.get('channel')
    if not channel:
        logger.error(f'deleteRecord[dataError.] data: {data}')
        return_dict[provider]['message'] = f'deleteRecord[dataError.] data: {data}'
        return text(json.dumps(return_dict))
    protocol, record, domain = parseProtocolRecordDomain(channel)
    wafInfo = await M['QINGSONG_waf_info'].find_one({'domain': domain, 'record': record})
    domain_id = wafInfo.get('domain_id')

    col_task = f'{provider}_waf_task'
    col_info = f'{provider}_waf_info'
    theD = getTheD(channel)
    domainInfo = await M.domain.find_one({'domain': theD})
    user_id = domainInfo.get('user_id')
    rUpdateDomain = await M.domain.update_many({'domain': theD}, {'$unset': {'waf': ''}})
    rDeleteTask = await M[col_task].delete_one({'domain': theD})
    rDeleteInfo = await M[col_info].delete_one({'domain': domain, 'record': record})
    logger.info(f'deleteRecord[4recordUpdateDone.] channel: {channel}|| user_id: {user_id}|| rUpdateDomain: ({rUpdateDomain.modified_count}/{rUpdateDomain.matched_count})|| rDeleteTask: {rDeleteTask.deleted_count}|| rDeleteInfo: {rDeleteInfo.deleted_count}')

    request.app.QS.channel = channel
    rDeleteRecordSet = await request.app.QS.delete_record_set(domain_id, record)
    rDict = {provider: rDeleteRecordSet}
    if rDeleteRecordSet['return_code'] != 0:
        logger.error(f'deleteRecord[recordDeleteError.] channel: {channel}|| rDeleteRecordSet: {rDeleteRecordSet}')
        return text(json.dumps(rDeleteRecordSet))
    logger.info(f'deleteRecord[recordDeleteDone.] channel: {channel}|| rDeleteRecordSet: {rDeleteRecordSet}')
    return text(json.dumps({provider: rDeleteRecordSet}))


@waf_bp.post('/get_domain_status')
async def getDomainStatus(request):
    '''
        0：显示“开通waf”
        1：显示“待审核”
        2：显示“审核不通过”
        3：显示“配置”+“统计”
    '''
    provider = 'QINGSONG'
    return_dict = {'return_code': -1, 'message': '...'}
    M = request.app.M
    data = request.json
    channel = data.get('channel')
    if not channel:
        logger.error(f'getDomainStatus[dataError.] data: {data}')
        return_dict['message'] = f'getDomainStatus[dataError.] data: {data}'
        return text(json.dumps(return_dict))
    protocol, record, domain = parseProtocolRecordDomain(channel)
    wafInfo = await M['QINGSONG_waf_info'].find_one({'domain': domain, 'record': record})
    if wafInfo is None:
        return_dict['return_code'] = 0
        return_dict['message'] = 'success'
        return_dict['data'] = {}
        logger.error(f'getDomainStatus[wafInfo is None.] channel: {channel}|| return_dict: {return_dict}')
        return text(json.dumps(return_dict))
    domain_status = wafInfo.get('domain_status')
    return_dict['return_code'] = 0
    return_dict['message'] = 'success'
    status = 0
    if domain_status == -1:
        status = 1
    elif domain_status == -2:
        status = 2
    else:
        status = 3
    return_dict['data'] = {'status': status}

    # logger.info(f'getDomainStatus channel: {channel}|| return_dict: {return_dict}')
    return text(json.dumps(return_dict))


class ReqSender:

    def __init__(self, M):
        self.M = M
        self.channel = None

    async def delete_record_set(self, domain_id, record_name):
        ''' ... '''
        tempData = {
            'action': 'delete_record_set',
            'domain_id': domain_id,
            'record_name': record_name,
        }
        return await self.postAction(tempData)

    async def delete_cert(self, cert_id):
        ''' ... '''
        tempData = {
            'action': 'delete_cert',
            'cert_id': cert_id,
        }
        return await self.postAction(tempData)

    async def set_https_port(self, record_id, port=443):
        ''' ... '''
        tempData = {
            'action': 'set_https_port',
            'record_id': record_id,
            'port': port,
        }
        return await self.postAction(tempData)

    async def add_cert(self, name, cert_name, cert, key_name, key):
        ''' ... '''
        tempData = {
            'action': 'add_cert',
            'name': name,
            'crt_name': cert_name,
            'crt': cert,
            'key_name': key_name,
            'key': key,
        }
        return await self.postAction(tempData)

    async def add_record_site(self, domain_id, name, source_site, var_dict={}):
        '''
            keys of var_dict maybe: port, view, ttl
            {'record_id': '1525Q3754609439', 'cname': '42e87675846d2cd0.7cname.com'}
        '''
        tempData = {
            'action': 'add_record_site',
            'domain_id': domain_id,
            'name': name,
            'source_site': source_site,
        }
        for k, v in var_dict.items():
            if v:
                tempData[k] = v
        return await self.postAction(tempData)

    async def delete_record_site(self, record_id):
        ''' ... '''
        tempData = {
            'action': 'delete_record_site',
            'record_id': record_id,
        }
        return await self.postAction(tempData)

    async def delete_record(self, record_id):
        ''' ... '''
        tempData = {
            'action': 'delete_record',
            'record_id': record_id,
        }
        return await self.postAction(tempData)

    async def modify_record_site(self, record_id, source_site, var_dict):
        ''' ... '''
        tempData = {
            'action': 'modify_record_site',
            'record_id': record_id,
            'source_site': source_site,
        }
        for k,v in var_dict.items():
            if v:
                tempData[k] = v
        return await self.postAction(tempData)

    async def modify_record(self, record_id, var_dict):
        ''' ... '''
        tempData = {
            'action': 'modify_record',
            'record_id': record_id,
        }
        for k,v in var_dict.items():
            if v:
                tempData[k] = v
        return await self.postAction(tempData)

    async def set_https_record(self, domain_id, record_name, enable, cert_id):
        ''' ... '''
        tempData = {
            'action': 'set_https_record',
            'domain_id': domain_id,
            'record_name': record_name,
            'enable': enable,
            'cert_id': cert_id,
        }
        return await self.postAction(tempData)

    async def cert_list(self):
        ''' ... '''
        tempData = {
            'action': 'cert_list',
        }
        return await self.postAction(tempData)

    async def record_site_list(self, domain_id):
        ''' ... '''
        tempData = {
            'action': 'record_site_list',
            'domain_id': domain_id,
        }
        return await self.postAction(tempData)

    async def record_list(self, domain_id):
        ''' ... '''
        tempData = {
            'action': 'record_list',
            'domain_id': domain_id,
        }
        return await self.postAction(tempData)


    async def record_waf(self, domain_id, record_name):
        ''' ... '''
        tempData = {
            'action': 'record_waf',
            'domain_id': domain_id,
            'record_name': record_name,
        }
        return await self.postAction(tempData)


    async def domain_waf(self, domain_id):
        ''' ... '''
        tempData = {
            'action': 'domain_waf',
            'domain_id': domain_id,
        }
        return await self.postAction(tempData)


    async def waf_defense_aggregate(self, domain_id, record, start_day, end_day):
        ''' ... '''
        tempData = {
            'action': 'waf_defense_aggregate',
            'domain_id': domain_id,
            'record_name': record, # optional
            'start_day': start_day,
            'end_day': end_day,
        }
        return await self.postAction(tempData)


    async def waf_log_detail(self, domain_id, log_id, log_time):
        ''' ... '''
        tempData = {
            'action': 'waf_log_detail',
            'domain_id': domain_id,
            'log_id': log_id,
            'log_time': log_time,
        }
        return await self.postAction(tempData)


    async def waf_report(self, domain_id, record_name, other_fields):
        ''' atk_type, atk_ip, url, start_time, end_time, page, page_size '''
        tempData = {
            'action': 'waf_report',
            'domain_id': domain_id,
            'record_name': record_name,
        }
        for k, v in other_fields.items():
            if v is not None:
                tempData[k] = v
        return await self.postAction(tempData)


    async def set_default_waf(self, domain_id, record_name, enable):
        ''' ... '''
        tempData = {
            'action': 'set_default_waf',
            'domain_id': domain_id,
            'record_name': record_name,
            'enable': enable,
        }
        return await self.postAction(tempData)


    async def default_waf_rule_list(self, domain_id, record_name):
        ''' ... '''
        tempData = {
            'action': 'default_waf_rule_list',
            'domain_id': domain_id,
            'record_name': record_name,
        }
        return await self.postAction(tempData)


    async def waf_rule_list(self, domain_id, record_name):
        ''' ... '''
        tempData = {
            'action': 'waf_rule_list',
            'domain_id': domain_id,
            'record_name': record_name,
        }
        return await self.postAction(tempData)


    async def delete_domain(self, domain_id):
        ''' {'status': -1, 'domain_id': '393838'} '''
        tempData = {
            'action': 'delete_domain',
            'domain': domain_id,
        }
        return await self.postAction(tempData)


    async def all_domain(self):
        '''
        {'action': 'all_domain', 'message': 'success', 'data': {'domain_list': [{'status': -1, 'domain': 'chinacache.com', 'type': 1, 'id': '393838', 'service': {}}, {'status': -1, 'domain': 'test0328.com', 'type': 1, 'id': '393835', 'service': {}}]}, 'return_code': 0}
        '''
        tempData = {
            'action': 'all_domain',
        }
        return await self.postAction(tempData)


    async def add_domain(self, domain):
        ''' {'status': -1, 'domain_id': '393838'} '''
        tempData = {
            'action': 'add_domain',
            'domain': domain,
            'type': 1,
        }
        return await self.postAction(tempData)


    async def add_record(self, domain_id, name, ip, var_dict={}):
        '''
            keys of var_dict maybe: port, view, ttl
            {'record_id': '1525Q3754609439', 'cname': '42e87675846d2cd0.7cname.com'}
        '''
        tempData = {
            'action': 'add_record',
            'domain_id': domain_id,
            'name': name,
            'ip': ip,
        }
        for k, v in var_dict.items():
            if v:
                tempData[k] = v
        return await self.postAction(tempData)


    async def third_buy_waf(self, buy_id=1, quantity=1, timeMonth=12):
        ''' {'id': [193, 194]} '''
        tempData = {
            'action': 'third_buy_waf',
            'buy_id': buy_id,
            'quantity': quantity,
            'time': timeMonth,
        }
        return await self.postAction(tempData)


    async def service_bind(self, domain_id, service_id):
        ''' no data part '''
        tempData = {
            'action': 'service_bind',
            'domain_id': domain_id,
            'service_id': service_id,
        }
        return await self.postAction(tempData)


    async def set_domain_defense(self, domain_id, switch=1):
        ''' no data part '''
        tempData = {
            'action': 'set_domain_defense',
            'domain_id': domain_id,
            'switch': switch,
        }
        return await self.postAction(tempData)


    async def set_record_defense(self, domain_id, record_name, switch=1):
        ''' data based on the domain status 0 '''
        tempData = {
            'action': 'set_record_defense',
            'domain_id': domain_id,
            'record_name': record_name,
            'switch': switch,
        }
        return await self.postAction(tempData)


    async def set_waf_defense(self, domain_id, switch=1):
        ''' no data part '''
        tempData = {
            'action': 'set_waf_defense',
            'domain_id': domain_id,
            'switch': switch,
        }
        return await self.postAction(tempData)


    async def set_record_waf_defense(self, domain_id, record_name, default=1, switch=1):
        ''' default==0: customized waf mode; default==1: default waf mode
            switch in [0, 1, 2, 3]
        '''
        tempData = {
            'action': 'set_record_waf_defense',
            'domain_id': domain_id,
            'record_name': record_name,
            'default': default,
            'switch': switch,
        }
        return await self.postAction(tempData)


    async def get_domain_info(self, domain_id='393838'):
        tempData = {
            'action': 'get_domain_info',
            'domain_id': domain_id,
        }
        return await self.postAction(tempData)


    async def set_default_waf_rule_enable(self, domain_id, record_name, rule_id, enable=1):
        tempData = {
            'action': 'set_default_waf_rule_enable',
            'domain_id': domain_id,
            'record_name': record_name,
            'rule_id': rule_id,
            'enable': enable,
        }
        return await self.postAction(tempData)


    async def set_waf_rule_enable(self, rule_id, enable=1):
        tempData = {
            'action': 'set_waf_rule_enable',
            'rule_id': rule_id,
            'enable': enable,
        }
        return await self.postAction(tempData)


    async def postAction(self, tempData):
        provider = 'QINGSONG'
        if not self.channel:
            raise Exception(f'postAction channel error.')
        token = await getToken(self.M, self.channel)
        if not token:
            e_dict = {}
            e_dict.setdefault(provider, {}).update({'return_code': -1, 'msg': 'token is not existed.'})
            # e_dict['return_code'] = -1
            # e_dict['msg'] = f'token is not existed.'
            raise Exception(json.dumps(e_dict))

            # token = QS_TOKEN # solid
            # logger.info(f'postAction[token: findNothingFromMongo->userDefaultToken.] token: {token}')
        else:
            logger.info(f'postAction[tokenFromMongo.] token: {token}')

        postData = {'token': token}
        postData.update(tempData)
        logger.info(f'postAction postData: {postData}')
        r = await self.dopost(postData)
        return json.loads(r)


    async def dopost(self, body, url=QSURL):
        conn = aiohttp.TCPConnector(verify_ssl=False)
        # timeout = aiohttp.ClientTimeout(sock_connect=120, sock_read=120)

        async with aiohttp.ClientSession(connector=conn) as session:
        # async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
            async with session.post(url, data=body) as response:
                return await response.text()


def parseProtocolRecordDomain(channel):
    if not channel.startswith('http'):
        return None, None, None

    channelProtocol = 'https' if channel.startswith('https') else 'http'
    netloc = parse.urlparse(channel).netloc
    netlocArr = netloc.split('.')
    length = len(netlocArr)
    if length < 3:
        return channelProtocol, '', netloc
    return channelProtocol, netlocArr[0], '.'.join(netlocArr[1:])


async def waf_rest(request, product, channel):
    '''
        domain: 域名 -> channel
        src_type: 1 ip回源 & 2 域名回源
        src_address: 回源值 域名回源就是域名,ip回源就是ip
        src_port: 回源端口
        src_host: 回源host
        ssl_status: 是否启用https
        cert_name: 证书名称 -> cert_id
        default_waf_mode: 默认规则防御模式
        self_waf_mode: 自定义规则防御模式
    '''
    M = request.app.M
    protocol, record, domain = parseProtocolRecordDomain(channel)
    theD = getTheD(channel)

    response_dict = {product: {'return_code': 0, 'message': ''}}

    col_info = f'{product}_waf_info'
    wafInfo = await M[col_info].find_one({'record': record, 'domain': domain})
    record = wafInfo.get('record')
    if wafInfo.get('cInfo') is None:
        response_dict[product]['return_code'] = -1
        response_dict[product]['message'] = 'cInfo is None.'
        return text(json.dumps(response_dict))

    src_address = wafInfo['cInfo']['src_address']
    src_type = int(wafInfo['cInfo']['src_type'])
    src_port = int(wafInfo['cInfo']['src_port'])
    ssl_status = int(wafInfo['cInfo']['ssl_status'])
    cert_id = wafInfo['cInfo'].get('cert_id')
    default_waf_mode = int(wafInfo['cInfo']['default_waf_mode'])
    self_waf_mode = int(wafInfo['cInfo']['self_waf_mode'])

    alreadyBinded = False

    domainInfo, return_code_domain = await check_domain(request, channel)
    domain_status = domainInfo['status']

    domain_id = domainInfo.get('id')
    rUpdate = await M[col_info].update_many({'domain': domain}, {'$set': {'domain_id': domain_id, 'domain_status': domain_status}})
    logger.info(f'waf_rest channel: {channel}|| domainInfo: {domainInfo}|| rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')

    if domain_status in [-1, -2]:
        DOMAIN_STATUS_MESSAGE = {
            -1: '域名待审核',
            -2: '域名审核不通过'
        }
        response_dict[product]['message'] = DOMAIN_STATUS_MESSAGE[domain_status]
        response_dict[product]['return_code'] = return_code_domain
        return text(json.dumps(response_dict))

    service = domainInfo.get('service')
    if service:
        alreadyBinded = True

    try:

        #---{'record_id': '1525Q3754609439', 'cname': '42e87675846d2cd0.7cname.com'}
        var_dict_rcd = {}
        var_dict_rcd['port'] = src_port
        if src_type == 1:
            rAddRecord = await request.app.QS.add_record(domain_id=domain_id, name=record, ip=src_address, var_dict=var_dict_rcd)
            if rAddRecord['return_code'] != 0:
                logger.error(f'waf_rest[add_record error.] rAddRecord: {rAddRecord}')
                response_dict.setdefault(product, {}).update(rAddRecord)
                return text(json.dumps(response_dict))
            record_id = rAddRecord['data']['record_id']
            logger.info(f'waf_rest[add_record done.] channel: {channel}|| rAddRecord: {rAddRecord}')
        else:
            rAddRecordSite = await request.app.QS.add_record_site(domain_id=domain_id, name=record, source_site=src_address, var_dict=var_dict_rcd)
            if rAddRecordSite['return_code'] != 0:
                logger.error(f'waf_rest[add_record_site error.] rAddRecordSite: {rAddRecordSite}')
                response_dict.setdefault(product, {}).update(rAddRecordSite)
                return text(json.dumps(response_dict))
            record_id = rAddRecordSite['data']['record_id']
            logger.info(f'waf_rest[add_record_site done.] channel: {channel}|| rAddRecordSite: {rAddRecordSite}')
        rUpdate = await M[col_info].update_one({'domain': domain, 'record': record}, {'$set': {'record_id': record_id}})
        logger.info(f'waf_rest[recordIdUpdateDone.] channel: {channel}|| rUpdate: ({rUpdate.modified_count}/{rUpdate.matched_count})')

        service_id = None
        buy_id = 1
        timeMonth = 12
        if alreadyBinded is False:
            #---for service_id
            #---{'action': 'third_buy_waf', 'message': 'success', 'data': {'id': [193]}, 'return_code': 0}
            rThirdBuyWaf = await request.app.QS.third_buy_waf(buy_id=buy_id, timeMonth=timeMonth)
            if rThirdBuyWaf.get('return_code') != 0:
                logger.error(f'waf_rest[third_buy_waf error.] rThirdBuyWaf: {rThirdBuyWaf}')
                response_dict.setdefault(product, {}).update(rThirdBuyWaf)
                return text(json.dumps(response_dict))
            service_id = rThirdBuyWaf['data']['id'][0]
            logger.info(f'waf_rest[third_buy_waf done.] channel: {channel}|| service_id: {service_id}|| buy_id: {buy_id}|| timeMonth: {timeMonth}')

            #---for service_bind
            #---{'action': 'service_bind', 'message': 'success', 'return_code': 0}
            rBind = await request.app.QS.service_bind(domain_id, service_id)
            if rBind.get('return_code') != 0:
                logger.error(f'waf_rest[service_bind error.] rBind: {rBind}')
                response_dict.setdefault(product, {}).update(rThirdBuyWaf)
                return text(json.dumps(response_dict))
            logger.info(f'waf_rest[service_bind done.] channel: {channel}|| domain_id: {domain_id}|| service_id: {service_id}')

        #---for set_domain_defense
        #---{'action': 'set_domain_defense', 'message': '域名需要审核通过，才能开启防御服务', 'return_code': 4}
        #---{'action': 'set_domain_defense', 'message': '防御服务未分配节点', 'return_code': 5}
        rSetDomainDefense = await request.app.QS.set_domain_defense(domain_id, switch=1)
        if rSetDomainDefense.get('return_code') != 0:
            logger.error(f'waf_rest[set_domain_defense error.] rSetDomainDefense: {rSetDomainDefense}')
            response_dict.setdefault(product, {}).update(rSetDomainDefense)
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[set_domain_defense done.] channel: {channel}|| domain_id: {domain_id}|| switch: 1')

        #---for set_record_defense
        #---{'action': 'set_record_defense', 'message': '域名没有绑定防御服务', 'return_code': 2}
        rSetRecordDefense = await request.app.QS.set_record_defense(domain_id, record, switch=1)
        if rSetRecordDefense.get('return_code') != 0:
            logger.error(f'waf_rest[set_record_defense error.] rSetRecordDefense: {rSetRecordDefense}')
            response_dict.setdefault(product, {}).update(rSetRecordDefense)
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[set_record_defense done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| switch: 1')

        #---for set_waf_defense
        #---{'action': 'set_waf_defense', 'message': 'success', 'return_code': 0}
        rSetWafDefense = await request.app.QS.set_waf_defense(domain_id, switch=1)
        if rSetWafDefense.get('return_code') != 0:
            response_dict.setdefault(product, {}).update(rSetWafDefense)
            logger.error(f'waf_rest[set_waf_defense error.] rSetWafDefense: {rSetWafDefense}')
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[set_waf_defense done.] channel: {channel}|| domain_id: {domain_id}|| switch: 1')

        #---for set_record_waf_defense
        #---{'action': 'set_record_waf_defense', 'message': '域名没有绑定防御服务', 'return_code': 2}
        # rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record, switch=1)
        # if rSetRecordWafDefense.get('return_code') != 0:
        #     response_dict.setdefault(product, {}).update(rSetRecordWafDefense)
        #     logger.error(f'waf_rest[set_record_waf_defense error.] rSetRecordWafDefense: {rSetRecordWafDefense}')
        #     return text(json.dumps(response_dict))
        # logger.info(f'waf_rest[set_record_waf_defense done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| switch: 1')

    except Exception:
        logger.error(f'waf_rest error: {traceback.format_exc()}')
        response_dict.setdefault(product, {}).update({'return_code': -1})
        return text(json.dumps(response_dict))
    else:
        # rUpdate = await M.waf_info.update_many({'domain_id': domain_id, 'record': record}, {'$set': {'all_steps_done': 1}})
        if service:
            logger.info(f'waf_rest[all steps finished.] channel: {channel}|| domain_id: {domain_id}|| record_id: {record_id}|| service: {service}')
        else:
            logger.info(f'waf_rest[all steps finished.] channel: {channel}|| domain_id: {domain_id}|| record_id: {record_id}|| service_id: {service_id}|| buy_id: {buy_id}|| timeMonth: {timeMonth}')

    #---for https_enable
    if ssl_status == 1:
        rSetHttpsPort = await request.app.QS.set_https_port(record_id)
        if rSetHttpsPort.get('return_code') != 0:
            response_dict.setdefault(product, {}).update(rSetHttpsPort)
            logger.error(f'waf_rest[set_https_port error.] rSetHttpsPort: {rSetHttpsPort}')
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[set_https_port done.] channel: {channel}|| record_id: {record_id}')

        if cert_id is None:
            response_dict.setdefault(product, {}).update({'return_code': -1})
            logger.error(f'waf_rest[cert_id is None.] channel: {channel}')
            return text(json.dumps(response_dict))

        rSetHttpsRecord = await request.app.QS.set_https_record(domain_id, record, ssl_status, cert_id)
        if rSetHttpsRecord['return_code'] != 0:
            response_dict.setdefault(product, {}).update(rSetHttpsRecord)
            logger.error(f'waf_rest[set_https_record error.] rSetHttpsRecord: {rSetHttpsRecord}')
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[set_https_record done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| ssl_status: {ssl_status}|| cert_id: {cert_id}')

    #---default & self waf mode
    if default_waf_mode in [0, 1, 2, 3]:
        #---default: 1
        rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record, default=1, switch=default_waf_mode)
        if rSetRecordWafDefense.get('return_code') != 0:
            response_dict.setdefault(product, {}).update(rSetRecordWafDefense)
            logger.error(f'waf_rest[set_record_waf_defense error.] channel: {channel}|| rSetRecordWafDefense: {rSetRecordWafDefense}')
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[default_waf_mode done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| default: 1|| switch: {default_waf_mode}')
        if default_waf_mode == 0:
            logger.warn(f'waf_rest[default_waf_mode closed.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| default: 1|| switch: {default_waf_mode}')

    if self_waf_mode in [0, 1]:
        #---default: 0
        rSetRecordWafDefense = await request.app.QS.set_record_waf_defense(domain_id, record, default=0, switch=self_waf_mode)
        if rSetRecordWafDefense.get('return_code') != 0:
            response_dict.setdefault(product, {}).update(rSetRecordWafDefense)
            logger.error(f'waf_rest[set_record_waf_defense error.] channel: {channel}|| rSetRecordWafDefense: {rSetRecordWafDefense}')
            return text(json.dumps(response_dict))
        logger.info(f'waf_rest[default_waf_mode done.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| default: 1|| switch: {default_waf_mode}')
        if self_waf_mode == 0:
            logger.warn(f'waf_rest[default_waf_mode closed.] channel: {channel}|| domain_id: {domain_id}|| record: {record}|| default: 1|| switch: {default_waf_mode}')

    #---update the global status of whole task
    rUpdate = await M[f'{product}_waf_task'].update_one({'domain': theD}, {'$set': {'status': 2}})
    logger.info(f'waf_rest[create done.] channel: {channel}|| status: 2')
    #---mark creation finished.
    rGetDomainInfo = await request.app.QS.get_domain_info(domain_id=domain_id)
    if rGetDomainInfo['return_code'] != 0:
        logger.error(f'waf_rest[get_domain_info error.] rAddRecord: {rGetDomainInfo}')
        response_dict.setdefault(product, {}).update(rGetDomainInfo)
        return text(json.dumps(response_dict))
    domain_status = rGetDomainInfo['data']['status']
    response_dict[product]['data'] = {'status': domain_status}

    return text(json.dumps(response_dict))


async def clearCerts(request, channel='http://itest.chinacache.com'):
    occupied = await check_record(request, domain_id='393838', channel=channel, total_list=True)
    s_dict = {'id': '333330'}
    totals = await get_cert_info(request, s_dict, channel=channel, total_list=True)
    useless = list(set(totals) ^ set(occupied))
    logger.debug(f'clearCerts occupied: {occupied}|| totals: {totals}|| useless: {useless}')
    request.app.QS.channel = channel
    [await request.app.QS.delete_cert(c_id) for c_id in useless]
    totals_new = await get_cert_info(request, s_dict, channel=channel, total_list=True)
    logger.debug(f'clearCerts occupied: {occupied}|| totals_new: {totals_new}')


# @waf_bp.get('/test/<flag>')
@waf_bp.route('/test/<flag>', methods=['GET', 'POST'])
async def test_anything(request, flag):
    st = time.time()
    M = request.app.M

    # request.json['hello_name'] = 'lym'
    # logger.info(request.json)

    # result = await M.waf_info.find().to_list(2)

    #---check_record
    if flag == 'check_record':
        # result, return_code = await check_record(request, domain_id='393838', channel='http://itest.chinacache.com', cert_list=True)
        result, return_code = await check_record(request, domain_id='32303636', channel='http://www.chinacache.com')

    #---check_domain
    '''
    {'status': 2, 'domain': 'chinacache.com', 'type': 1, 'id': '393838', 'service': {'service_id': 283, 'left_days': 331, 'server_name': '高级版WAF防御套餐', 'defense_days': 34}}
    '''
    if flag == 'check_domain':
        result, return_code = await check_domain(request, channel='http://itest.chinacache.com')

    #---get_cert_info
    if flag == 'get_cert_info':
        # s_dict = {'name': 'mzr_delete_final_1_2211'}
        s_dict = {'id': '333330'}
        result = await get_cert_info(request, s_dict, channel='http://itest.chinacache.com', total_list=True)

    if flag == 'index_information':
        col = 'QINGSONG_waf_info'
        result = await M[col].index_information()

    if flag == 'clear_certs':
        result = await clearCerts(request)

    '''
    rUpdate.raw_result: {'n': 1, 'nModified': 1, 'opTime': {'ts': Timestamp(1565577355, 1), 't': 33}, 'electionId': ObjectId('7fffffff0000000000000021'), 'ok': 1.0, 'operationTime': Timestamp(1565577355, 1), '$clusterTime': {'clusterTime': Timestamp(1565577355, 1), 'signature': {'hash': b'\x08\xe3=a\x11\xf9\xf41}\xc7\xe8?\r\xac\xba\xf2>\xaf\xfbv', 'keyId': 6696496593111089153}}, 'updatedExisting': True}
    '''
    if flag == 'update_mongo':
        rUpdate = await M.QINGSONG_waf_info_0.update_one({"domain" : "chinacache.com", "record": "itest"}, {"$set": {"record_id": 1937}})
        result = rUpdate.raw_result

    logger.info(f'test_anything[It takes {time.time()-st} seconds.] result: {result}')

    return text('ok')
