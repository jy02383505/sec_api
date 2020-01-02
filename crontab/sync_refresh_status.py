"""
同步刷新状态
"""
import datetime

from mongo_db import refresh_task_db, refresh_log_db
from api_conf import FuseApiConfig as base_config

from cc_crontab.cc_api import CCAPI

TIMEOUT = 60 * 20

def update_task_status(task_db, search_sql, update_doc):
    """更新任务信息"""
    task_db.update_one(search_sql, {'$set': update_doc})

    if 'status' in update_doc:
        log_db = refresh_log_db()

        update_log_doc = {
            'status': update_doc['status']
        }

        log_db.update_many(search_sql, {'$set': update_log_doc})


def sync_check_cc_result(opt, log, refresh_db):
    """检查蓝汛刷新结果"""
    flag = log.get('flag', '')
    refresh_info = log.get('refresh_info', {})
    refresh_result = log.get('refresh_result', {})
    check_result = log.get('check_result', {})

    task_id = refresh_info.get(opt, {}).get('task_id', '')
    cms_username = log.get('cms_username', '')
    cms_password = log.get('cms_password', '')
    args = {
        'cms_username': cms_username,
        'cms_password': cms_password,
        'task_id': task_id,
    }

    cc_check_result = CCAPI.domain_refresh_status(args)

    search_sql = {'flag': flag}

    if 'err_msg' in cc_check_result:

        refresh_result[opt] = cc_check_result['err_msg']

        update_doc = {
            'status': base_config.REFRESH_FAIL,
            'refresh_result': refresh_result
        }

        update_task_status(refresh_db, search_sql, update_doc)
    else:
        refresh_status = cc_check_result.get(
            'refresh_status', base_config.REFRESH_FAIL)
        link_result = cc_check_result.get('link_result')

        check_result[opt] = refresh_status
        refresh_result[opt] = link_result

        update_doc = {
            'check_result': check_result,
            'refresh_result': refresh_result
        }

        update_task_status(refresh_db, search_sql, update_doc)

    log['check_result'] = check_result


def get_refresh_info():
    """检查刷新状态"""
    now = datetime.datetime.now()

    task_db = refresh_task_db()

    search_sql = {
        'status': base_config.REFRESH_CONDUCT
    }

    record_list = task_db.find(search_sql)

    for log in record_list:
        flag = log.get('flag', '')
        opts = log.get('opts', [])
        send_status = log.get('send_status', {})


        check_result = log.get('check_result', {})

        start_time = log.get('start_time', None)
        if not start_time or (now - start_time).seconds > TIMEOUT:
            update_doc = {'status': base_config.REFRESH_FAIL}
            task_db.update_one({'flag': flag}, {'$set': update_doc})

        for opt in opts:
            if opt in send_status \
                    and send_status[opt] == base_config.SEND_SUCCESS:
                    if  opt not in check_result or \
                        check_result.get(opt) == base_config.REFRESH_CONDUCT:
                        if opt == 'CC':
                            sync_check_cc_result(opt, log, task_db)

        check_result = log.get('check_result', {})

        send_succ_list = []
        for i in send_status:
            if send_status[i] == base_config.SEND_SUCCESS:
                send_succ_list.append(i)

        check_succ_list = []
        for i in check_result:
            if check_result[i] == base_config.SEND_SUCCESS:
                check_succ_list.append(i)

        opts.sort()
        send_succ_list.sort()
        check_succ_list.sort()

        if opts == send_succ_list == check_succ_list:
            update_doc = {'status': base_config.REFRESH_SUCCESS}
            search_sql = {'flag': flag}
            update_task_status(task_db, search_sql, update_doc)

if __name__ == '__main__':
    get_refresh_info()