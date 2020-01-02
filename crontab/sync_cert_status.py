
import os
import sys
import datetime


sys.path.append(
    os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))

from mongo_db import cert_db, cert_opt_db

from api_conf import FuseApiConfig as base_config

from cc_crontab.cc_api import CCAPI

TIMEOUT = 60 * 30


def sync_check_cc_result(opt, log, cert_info):
    """同步结果"""

    cc_args = log.get('send_info', {}).get(opt, {})
    check_result = log.get('check_result', {})

    check_result[opt] = 0
    try:
        api_res = CCAPI.check_sslcert(cc_args)
        if api_res:
            check_result[opt] = 1

    except Exception as e:
        print(e)
        check_result[opt] = 2

    log['check_result'] = check_result

    cert_info.update_one(
        {'cert_name': log['cert_name']},
        {'$set': {'check_result': check_result}})

    return check_result


def cc_update_cert(opt, log, cert_info):
    """cc 更新证书"""

    check_opt = {}
    update_name = log.get('update_name', '')
    cert_name = log.get('cert_name', '')

    bak_search_sql = {
        'cert_name': update_name
    }

    update_task = cert_info.find_one(bak_search_sql)
    print(11111,
          update_task.get('cert_name', ''), update_task.get('status', ''))

    check_opt[opt] = 0
    if update_task.get('status', 0) == 1:

        old_send_info = log['send_info'][opt]
        new_send_info = update_task['send_info'][opt]

        crt_new_id = new_send_info['cert_id']
        cms_username = new_send_info['cms_username']
        crt_old_id = old_send_info['cert_id']

        cc_args = {
            "crt_old_id": crt_old_id,
            'cms_username': cms_username,
            "crt_new_id": crt_new_id
        }
        print(cc_args)

        try:
            api_res = CCAPI.update_sslcert(cc_args)

            print(2222222, api_res)
            if api_res:
                """
                {"crt_old_id": "5d6d0818fd4a7477b8bc8c29",
                "crt_new_id": "5d6d0d75e2c9fb57cd25e5e7"}
                """
                update_task.pop("_id")
                update_task.pop("cert_name")
                update_task['update_name'] = ''

                new_send_info['cert_name'] = cert_name

                search_sql = {
                    'cert_name': cert_name
                }

                cert_info.update_one(search_sql, {'$set': update_task})
                cert_info.delete_one(bak_search_sql)

                check_opt[opt] = 1
        except Exception as e:
            print(e)
            check_opt[opt] = 2

    return check_opt


def sync_cc_cert_status():
    """同步cc 证书状态"""
    search_sql = {
        'status': {'$in': [0, 5]}
    }

    now = datetime.datetime.now()

    cert_info = cert_db()

    task_list = cert_info.find(search_sql)

    opt_db = cert_opt_db()


    for log in task_list:

        log.pop('cert')
        log.pop('key')

        opt_result = {}

        cert_name = log.get('cert_name', '')
        create_time = log.get('create_time')
        opts = log.get('opts', [])
        send_status = log.get('send_status', [])
        check_result = log.get('check_result', {})

        status = log.get('status', 0)

        task_search_sql = {
            'cert_name': cert_name
        }

        if (now - create_time).seconds > TIMEOUT:
            update_doc = {
                'status': 2
            }
            cert_info.update_one(task_search_sql, {"$set": update_doc})

            opt_result = check_result
            status = 2

        log_opt = ''

        need_log = False

        if status == 0:
            log_opt = 'is_create'

            for opt in opts:
                if opt in send_status and send_status[opt] == 1:
                    if opt not in check_result or check_result.get(opt) == 0:
                        if opt == 'CC':
                            opt_result = sync_check_cc_result(
                                opt, log, cert_info)


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
                search_sql = {'cert_name': cert_name}

                update_log_doc = {
                    'status': 1
                }

                cert_info.update_many(search_sql, {'$set': update_log_doc})
                need_log = True

        elif status == 5:
            log_opt = 'is_edit'

            for opt in opts:
                if opt == 'CC':
                    opt_result = cc_update_cert(opt, log, cert_info)
                    if opt_result[opt]:
                        need_log = True

        if need_log:
            opt_username = log.get('opt_username', '')

            log_doc = {
                'cert_name': cert_name,
                'opt_username': opt_username,
                'create_time': now,
                'log_opt': log_opt,
                'opt_result': opt_result

            }
            opt_db.insert_one(log_doc)

if __name__ == '__main__':
    sync_cc_cert_status()
