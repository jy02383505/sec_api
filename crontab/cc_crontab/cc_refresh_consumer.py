# -*- coding: utf-8 -*-
"""
处理cc url 刷新 nsq队列任务
"""
import os
import sys
import nsq
import json
import copy
import pymongo
import datetime
from urllib.parse import urlparse

sys.path.append(
    os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))

from config import nsq_config, mongo_config
from cc_api import CCAPI
from api_conf import FuseApiConfig as base_config
from mongo_db import refresh_task_db, conn_mongo_nsq_err_log


OPT = 'CC'

hosts = nsq_config
BASE_MAX_TRIES = 5
nsq_name = 'cdn_%s_refresh' % OPT.lower()


def process_message(message):
    """进程处理 """
    message.enable_async()

    try:
        exe_flag = False
        nsq_message = message.body.decode()

        nsq_message = json.loads(nsq_message)

        print(datetime.datetime.now(), message.attempts, nsq_message)

        if message.attempts == BASE_MAX_TRIES:
            err_log = conn_mongo_nsq_err_log()
            error_info = copy.deepcopy(nsq_message)
            error_info['error_datetime'] = datetime.datetime.now()

            err_log.insert(error_info)

        if nsq_message:
            """
            {
                'flag': 'c10f1f1c0d4898f3f44819eac0a2463f',
                'cms_username': 'msft-xztest',
                'urls': ['http://itestxz0021.chinacache.com/1.json'],
                'dirs': ['http://itestxz0021.chinacache.com/aa/']
            }
            """

            task_flag = nsq_message.get('flag', '')

            args = {
                'cms_username': nsq_message.get('cms_username', ''),
                'urls': nsq_message.get('urls', []),
                'dirs': nsq_message.get('dirs', []),
            }

            refresh_result = CCAPI.domain_refresh(args)

            task_id = refresh_result.get('task_id', '')

            send_result = base_config.SEND_SUCCESS
            if 'err_msg' in refresh_result or not task_id:
                send_result = base_config.SEND_FAIL

            refresh_task = refresh_task_db()

            search_sql = {'flag': task_flag}
            mlog = refresh_task.find_one(search_sql)

            if mlog:
                if send_result != base_config.SEND_SUCCESS:
                    mlog['status'] = base_config.REFRESH_FAIL

                mlog['send_status'][OPT] = send_result

                refresh_info = mlog.get('refresh_info', {})
                refresh_info[OPT] = {'task_id': task_id}
                mlog['refresh_info'] = refresh_info

                pid = refresh_task.update_one(search_sql,  {'$set': mlog})
                if pid:
                    exe_flag = True

            if exe_flag:
                message.finish()
            else:
                message.requeue()
        else:
            print('deferring processing')

    except Exception as e:
        print(e)
        message.requeue()

    return True

r = nsq.Reader(
    message_handler=process_message,
    lookupd_http_addresses=hosts,
    topic=nsq_name,
    channel=nsq_name,
)


nsq.run()

