#!/usr/bin/env python
# coding: utf-8

import traceback
from datetime import datetime, timedelta
from sys import exit
import asyncio
import json
import aiohttp
from motor import motor_asyncio
import logging
import sys
import os
from sanic.response import text

sys.path.append(os.path.abspath(os.path.curdir))
from config import M_CONFIG, QSURL, QS_TOKEN

# logFormat = '%(asctime)s %(levelname)s %(name)s:%(lineno)d| %(message)s'
logFormat = "[%(asctime)s] %(process)d-%(levelname)s %(module)s::%(funcName)s():l%(lineno)d: %(message)s"

logging.basicConfig(
    format=logFormat,
    filename='logs/access.log',
    filemode='a+',
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)


M = motor_asyncio.AsyncIOMotorClient(M_CONFIG)['SEC_API']
# ---for test
# mongoURI = 'mongodb://bermuda:bermuda_refresh@223.202.203.52:27017/bermuda_s1'
# M = motor_asyncio.AsyncIOMotorClient(mongoURI)['bermuda_s1']

url_local = 'http://localhost:8800/waf/waf_rest'


async def dopost(session, url, body, isJson=False):
    if isJson:
        async with session.post(url, json=body) as response:
            logger.info(f'dopost[isJson.] url: {url}|| body: {body}')
            return json.loads(await response.text())
    else:
        async with session.post(url, data=body) as response:
            logger.info(f'dopost[isNotJson.] url: {url}|| body: {body}')
            return json.loads(await response.text())


async def getToken(record, domain):
    theD = f'{record}.{domain}'
    logger.info(f'getToken record: {record}|| domain: {domain}|| theD: {theD}')
    wafInfo = await M.domain.find_one({'domain': theD})
    user_id = wafInfo.get('user_id')
    u_p_info = await M.user_profile.find_one({'user_id': user_id})
    qingsongToken = u_p_info.get('qingsong_security_waf')
    return qingsongToken


async def getWafInfo():
    product = 'QINGSONG'
    col_info = f'{product}_waf_info'
    domain_list = await M[col_info].find({'domain_status': -1}).to_list(100)
    domainIdSet = set([i.get('domain_id') for i in domain_list])
    theDList = [{'record': i['record'], 'domain': i['domain'], 'domain_id': i['domain_id']} for i in domain_list if i['domain_id'] in domainIdSet]
    logger.info(f'getWafInfo domainIdSet: {domainIdSet}|| theDList: {theDList}')

    data = {}
    data['product'] = product
    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        for dInfo in theDList:
            theToken = await getToken(dInfo['record'], dInfo['domain'])
            newInfo = await dopost(session, QSURL, {'action': 'get_domain_info', 'domain_id': dInfo['domain_id'], 'token': theToken})
            logger.info(f'getWafInfo theToken: {theToken}|| newInfo: {newInfo}')
            return_code = newInfo.get('return_code')
            if return_code == 1:
                logger.info(f'getWafInfo[domain_idIsNotExisted.] domain_id: {dInfo["domain_id"]}')
                return text({'msg': 'domain_id is not existed.', 'return_code': -1})
            elif return_code == 0:
                domain_status = newInfo['data']['status']
                logger.info(f'getWafInfo[after get_domain_info.] status: {domain_status}|| domain_id: {dInfo["domain_id"]}')
                if domain_status >= 0:
                    rUpdate = await M[col_info].update_many({'domain_id': dInfo['domain_id']}, {'$set': {'domain_status': domain_status}})
                    logger.info(f'getWafInfo rUpdate: {rUpdate.modified_count}/{rUpdate.matched_count}')
                    # data.setdefault('channels', []).extend([f'http://{i["record"]}.{i["domain"]}' for i in domain_list if i['domain_id'] == dInfo['domain_id']])
                    #---get protocol from domain collection
                    domainInfo = await M.domain.find_one({'domain': f'{dInfo["record"]}.{dInfo["domain"]}'})
                    protocol = domainInfo.get('protocol')
                    data.setdefault('channels', []).append(f'{protocol}://{dInfo["record"]}.{dInfo["domain"]}')

            logger.info(f'getWafInfo[domain status changed to latest value successfully.] dInfo: {dInfo}|| data: {data}')
        response = await dopost(session, url_local, json.dumps(data), True)
    return response


if __name__ == '__main__':
    result = asyncio.get_event_loop().run_until_complete(getWafInfo())
    logger.info(f'QSCheck[getWafInfo request done.] result: {result}')
