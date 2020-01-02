"""
同步刷新状态
"""
import datetime

from mongo_db import preload_task_db, preload_log_db
from api_conf import FuseApiConfig as base_config

from cc_crontab.cc_api import CCAPI

TIMEOUT = 60 * 20

def update_task_status(task_db, search_sql, update_doc):
    """更新任务信息"""
    task_db.update_one(search_sql, {'$set': update_doc})

    if 'status' in update_doc:
        log_db = preload_log_db()

        update_log_doc = {
            'status': update_doc['status']
        }

        log_db.update_many(search_sql, {'$set': update_log_doc})


def sync_check_cc_result(opt, log, preload_db):
    """检查蓝汛刷新结果"""
    flag = log.get('flag', '')
    preload_info = log.get('preload_info', {})
    preload_result = log.get('preload_result', {})
    check_result = log.get('check_result', {})

    task_id = preload_info.get(opt, {}).get('task_id', '')
    cms_username = log.get('cms_username', '')
    cms_password = log.get('cms_password', '')
    args = {
        'cms_username': cms_username,
        'cms_password': cms_password,
        'task_id': task_id,
    }

    cc_check_result = CCAPI.domain_preload_status(args)
    print(1111111111, cc_check_result)
    """
    {
        'link_result': {
            'totalCount': 1, 'tasks': [{'url': 'http://hitest20.nubesi.com/static/image/6.png',
            'status': 'PROGRESS', 'percent': 0, 'task_id': 'aa29ebe850ca84b4f5395859b5ca4fa1'}]
        },
        'preload_status': 0,
        'err_msg': ''
    }
    """

    search_sql = {'flag': flag}

    if cc_check_result.get('err_msg', ''):

        preload_result[opt] = cc_check_result['err_msg']

        update_doc = {
            'status': base_config.PRELOAD_FAIL,
            'preload_result': preload_result
        }

        update_task_status(preload_db, search_sql, update_doc)
    else:
        preload_status = cc_check_result.get(
            'preload_status', base_config.PRELOAD_CONDUCT)

        print(22222, preload_status)
        link_result = cc_check_result.get('link_result')

        check_result[opt] = preload_status
        preload_result[opt] = link_result

        update_doc = {
            'check_result': check_result,
            'preload_result': preload_result
        }

        update_task_status(preload_db, search_sql, update_doc)

    log['check_result'] = check_result


def get_preload_info():
    """检查预热状态"""
    now = datetime.datetime.now()

    task_db = preload_task_db()

    search_sql = {
        'status': base_config.PRELOAD_CONDUCT
        # 'flag': '73c15b6ad3414e8c9d7711c98fbf9ab6'
    }

    record_list = task_db.find(search_sql)

    for log in record_list:
        flag = log.get('flag', '')
        opts = log.get('opts', [])
        send_status = log.get('send_status', {})


        check_result = log.get('check_result', {})

        start_time = log.get('start_time', None)
        if not start_time or (now - start_time).seconds > TIMEOUT:
            update_doc = {'status': base_config.PRELOAD_FAIL}
            task_db.update_one({'flag': flag}, {'$set': update_doc})

        for opt in opts:
            if opt in send_status \
                    and send_status[opt] == base_config.SEND_SUCCESS:
                    if  opt not in check_result or \
                        check_result.get(opt) == base_config.PRELOAD_CONDUCT:
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
            update_doc = {'status': base_config.PRELOAD_SUCCESS}
            search_sql = {'flag': flag}
            update_task_status(task_db, search_sql, update_doc)

if __name__ == '__main__':
    get_preload_info()