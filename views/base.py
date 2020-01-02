import sys
import time
import copy
import base64
import hashlib
import datetime
from random import Random

from OpenSSL import crypto
from sanic import Blueprint
from fuse_api.API import ExternalAPI
from sanic.response import json, html
from sanic.log import logger
from jinja2 import Environment, PackageLoader, select_autoescape
import logging

from lib.util import str_to_datetime, datetime_to_str, get_domain_status

log = logging.getLogger(__name__)

base_bp = Blueprint('base', url_prefix='base')

# 开启异步特性  要求3.6+
enable_async = sys.version_info >= (3, 6)

# jinjia2 config
env = Environment(
    loader=PackageLoader('views.base', '../templates'),
    autoescape=select_autoescape(['html', 'xml', 'tpl']),
    enable_async=enable_async)


async def template(tpl, **kwargs):
    the_template = env.get_template(tpl)
    rendered_template = await the_template.render_async(**kwargs)
    return html(rendered_template)


def random_str(random_length=16):
    base_str = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(random_length):
        base_str += chars[random.randint(0, length)]
    return base_str


def generate_secret(key):
    """
    生成客户密钥 ID：KEY
    :param key: USERNAME
    :return:
    """
    salt = random_str()
    cur_time = str(time.time())
    password_md5 = hashlib.md5(key.encode('utf-8')).hexdigest()
    secret_id = hashlib.md5(
        (password_md5 + salt + cur_time).encode('utf-8')).hexdigest().upper()
    password_final = base64.b64encode(secret_id.encode('ascii'))

    secret_key = password_final.decode()

    return secret_id, secret_key


@base_bp.route("/internal/create_user/", methods=['POST'])
async def create_user(request):
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    user_id = user_info.get('user_id', 0)
    is_api = user_info.get('is_api', False)
    now = datetime.datetime.now()

    user_doc = {
        "username": username,
        "user_id": user_id,
        "create_time": now,
        # "api_secret_id": "",
        # "api_secret_key": "",
        # "cms_username": "",
        # "cms_id": "",
        # "qingsong_token": ""
    }

    if is_api:
        secret_id, secret_key = generate_secret(username)

        user_doc['api_secret_id'] = secret_id
        user_doc['api_secret_key'] = secret_key
        user_doc['api_create_time'] = now
        user_doc['api_open'] = 1

    search_sql = {
        'username': username,
        'user_id': user_id
    }

    old_doc = await user_profile_db.find_one(search_sql)

    if old_doc:
        insert_id = await user_profile_db.replace_one(search_sql, user_doc)
    else:
        insert_id = await user_profile_db.insert_one(user_doc)

    flag = True if insert_id else False

    res = {
        'result': flag,
        'return_code': 0
    }

    return json(res)


@base_bp.route("/internal/update_user/", methods=['POST'])
async def update_user(request):
    """更新用户信息"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    user_id = user_info.get('user_id', 0)
    fields = user_info.get('fields', {})

    search_sql = {
        'username': username,
        'user_id': user_id
    }
    return_code = 0

    user_doc = await user_profile_db.find_one(search_sql)

    try:
        if not user_doc:
            return_code = 1
            assert False

        insert_id = await user_profile_db.update_one(
            search_sql, {'$set': fields})
        flag = True if insert_id else False
        print(insert_id)

    except AssertionError:
        print(user_doc)

    res = {
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/user_query/", methods=['POST'])
async def user_query(request):
    """用户查询"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    search_sql = {}

    username_list = user_info.get('username_list', '')
    return_type = user_info.get('return_type', 'is_dict')

    if return_type == 'is_list':
        result = []
    elif return_type == 'is_dict':
        result = {}

    if username_list:
        search_sql['username'] = {'$in': username_list}

    cms_username = user_info.get('cms_username', '')
    if cms_username:
        search_sql['cms_username'] = cms_username

    async for doc in user_profile_db.find(search_sql):
        temp_doc = copy.deepcopy(doc)
        temp_doc.pop('_id')
        temp_doc.pop('create_time')
        username = temp_doc.get('username', '')

        if return_type == 'is_list':
            result.append(temp_doc)
        elif return_type == 'is_dict':
            result[username] = temp_doc

    res = {'user_query': result}

    return json(res)


@base_bp.route("/internal/user_binding_cms/", methods=['POST'])
async def binding_user_cms(request):
    """用户关系绑定cms"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    cms_username = user_info.get('cms_username', '')
    username = user_info.get('username', '')
    user_id = user_info.get('user_id', '')
    cms_password = user_info.get('cms_password', '')
    contract_info = user_info.get('contract_info', [])

    search_sql = {
        'username': username,
        'user_id': user_id
    }

    user_doc = {
        'cms_password': cms_password,
        'cms_username': cms_username
    }

    contract = {}
    if contract_info:
        for c in contract_info:
            contract_name = c.get('contract_name', '')
            contract[contract_name] = {
                'start_time': c.get('start_time', ''),
                'end_time': c.get('end_time', ''),
                'product': c.get('product_list', [])
            }

    user_db_doc = await user_profile_db.find_one(search_sql)

    insert_id = None
    if user_db_doc:
        old_contract = user_db_doc.get('contract', {})
        old_contract.update(contract)

        user_doc['contract'] = old_contract
        insert_id = await user_profile_db.update_one(
            search_sql, {"$set": user_doc})

    flag = True if insert_id else False

    res = {'result': flag}

    return json(res)


@base_bp.route("/internal/user_relieve_cms_binding/", methods=['POST'])
async def admin_user_relieve_cms_binding(request):
    """用户关系解除cms绑定"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')

    search_sql = {
        'username': username,
    }

    user_doc = {
        'cms_username': ''
    }

    user_db_doc = await user_profile_db.find_one(search_sql)

    insert_id = None
    if user_db_doc:
        insert_id = await user_profile_db.update_one(
            search_sql, {"$set": user_doc})

    flag = True if insert_id else False

    res = {'result': flag}

    return json(res)


@base_bp.route("/internal/binding_user_contract/", methods=['POST'])
async def binding_user_contract(request):
    """绑定用户合同"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    contract = user_info.get('contract', '')

    search_sql = {
        'username': username,
    }
    return_code = 0

    user_doc = await user_profile_db.find_one(search_sql)

    try:
        if not user_doc:
            return_code = 1
            assert False

        contract_fields = user_doc.get('contract', {})
        contract_fields.update(contract)
        contract_dict = {
            'contract': contract_fields
        }

        insert_id = await user_profile_db.update_one(
            search_sql, {'$set': contract_dict})
        flag = True if insert_id else False

    except AssertionError:
        print(user_doc)

    res = {
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/relieve_user_contract/", methods=['POST'])
async def relieve_user_contract(request):
    """解除绑定用户合同"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    contract = user_info.get('contract', '')

    search_sql = {
        'username': username,
    }
    return_code = 0

    user_doc = await user_profile_db.find_one(search_sql)

    try:
        if not user_doc:
            return_code = 1
            assert False

        contract_fields = user_doc.get('contract', {})

        if contract in contract_fields:
            contract_fields.pop(contract)
            contract_dict = {
                'contract': contract_fields
            }

        insert_id = await user_profile_db.update_one(
            search_sql, {'$set': contract_dict})
        flag = True if insert_id else False

    except AssertionError:
        print(user_doc)

    res = {
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/set_secret_key/", methods=['POST'])
async def set_api_key(request):
    """对已有账号设置api_key"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')

    secret_id, secret_key = generate_secret(username)

    search_sql = {
        'username': username
    }

    user_doc = await user_profile_db.find_one(search_sql)

    now = datetime.datetime.now()

    insert_id = None
    if user_doc:
        update_doc = {
            "api_secret_id": secret_id,
            "api_secret_key": secret_key,
            "api_create_time": now,
            "api_open": 1
        }
        insert_id = await user_profile_db.update_one(
            search_sql, {'$set': update_doc})
    return_code = 0 if insert_id else 1

    res = {
        'secret_id': secret_id,
        'secret_key': secret_key,
        'create_time': datetime_to_str(now),
        'api_open': 1,
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/set_api_status/", methods=['POST'])
async def set_api_status(request):
    """设置api状态"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    status = user_info.get('status', 0)
    api_type = user_info.get('api_type', 'api_open')

    search_sql = {
        'username': username
    }

    update_doc = {
        api_type: status
    }
    print(3333333333, update_doc)
    insert_id = await user_profile_db.update_one(
        search_sql, {'$set': update_doc})
    return_code = 0 if insert_id else 1

    res = {
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/set_api_remove/", methods=['POST'])
async def set_api_remove(request):
    """删除api信息"""
    mongodb = request.app.M
    user_profile_db = mongodb.user_profile
    user_info = request.json

    username = user_info.get('username', '')
    api_type = user_info.get('api_type', 'api_open')

    search_sql = {
        'username': username
    }
    insert_id = None
    if api_type == 'api_open':
        update_doc = {
            'api_open': 0,
            'api_secret_id': '',
            'api_secret_key': '',
            'api_create_time': '',
        }
        insert_id = await user_profile_db.update_one(
            search_sql, {'$set': update_doc})
    return_code = 0 if insert_id else 1

    res = {
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/domain_create/", methods=['POST'])
async def domain_create(request):
    """域名添加"""
    mongodb = request.app.M
    domain_db = mongodb.domain
    request_body = request.json

    domain_info_list = request_body.get('domain_info_list', [])

    result_list = []
    for domain_info in domain_info_list:
        domain = domain_info.get('domain', '')
        protocol = domain_info.get('protocol', '')
        user_id = domain_info.get('user_id', '')

        domain_doc = {
            'domain': domain,
            'protocol': protocol,
            'user_id': user_id,
            'create_time': datetime.datetime.now()
        }

        search_sql = {
            'domain': domain,
            'protocol': protocol,
        }

        old_doc = await domain_db.find_one(search_sql)
        if not old_doc:

            insert_id = await domain_db.insert_one(domain_doc)

            insert_flag = True if insert_id else False

            if insert_flag:
                search_sql['insert_flag'] = insert_flag
                result_list.append(search_sql)

    res = {'result_list': result_list}

    return json(res)


@base_bp.route("/internal/domain_update/", methods=['POST'])
async def domain_update(request):
    """域名添加"""
    mongodb = request.app.M
    domain_db = mongodb.domain
    request_body = request.json

    domain = request_body.get('domain', '')
    protocol = request_body.get('protocol', '')
    fields = request_body.get('fields', {})

    search_sql = {
        'domain': domain,
        'protocol': protocol,
    }

    domain_doc = await domain_db.find_one(search_sql)

    result = False

    try:
        if not domain_doc:
            assert False

    except Exception as e:
        print(e)

    res = {'result': result}

    return json(res)


@base_bp.route("/internal/domain_query/", methods=['POST'])
async def domain_query(request):
    """域名列表查询"""
    mongodb = request.app.M
    domain_db = mongodb.domain
    user_profile_db = mongodb.user_profile
    domain_info = request.json

    domain_list = domain_info.get('domain_list', [])
    user_id_list = domain_info.get('user_id_list', [])
    return_type = domain_info.get('return_type', 'is_dict')

    search_sql = {}
    if domain_list:
        search_sql['domain'] = {'$in': domain_list}

    if user_id_list:
        search_sql['user_id'] = {'$in': user_id_list}

    if return_type == 'is_list':
        result_domain_query = []
    elif return_type == 'is_dict':
        result_domain_query = {}

    async for doc in domain_db.find(search_sql):
        temp_doc = copy.deepcopy(doc)
        temp_doc.pop('_id')
        temp_doc.pop('create_time')
        domain = temp_doc.get('domain', '')
        protocol = temp_doc.get('protocol', 'http')

        user_search_sql = {'user_id': temp_doc.get('user_id')}
        user_doc = await user_profile_db.find_one(user_search_sql)
        cms_id = user_doc.get('cms_username', '') if user_doc else ''
        temp_doc['cms_id'] = cms_id

        if return_type == 'is_list':
            result_domain_query.append(temp_doc)
        elif return_type == 'is_dict':
            url = '%s://%s' % (protocol, domain)
            result_domain_query[url] = temp_doc

    res = {'domain_query': result_domain_query}

    return json(res)


@base_bp.route("/internal/ssl_cert_create_or_edit/", methods=['POST'])
async def ssl_cert_create_or_edit(request):
    """证书上传"""
    mongodb = request.app.M
    cert_db = mongodb.cert
    user_db = mongodb.user_profile

    cert_info = request.json

    username = cert_info.get('username', '')
    remark = cert_info.get('remark', '')
    email = cert_info.get('email', 'test@chinacache.com')
    cert_name = cert_info.get('cert_name', '')
    cert_value = cert_info.get('cert_value', '')
    key_value = cert_info.get('key_value', '')
    cert_from = cert_info.get('cert_from', 0)
    period = cert_info.get('period', 0)

    opt_username = cert_info.get('opt_username', '')

    is_update = cert_info.get('is_update', 0)

    user_search_sql = {
        'username': username
    }
    user_doc = await user_db.find_one(user_search_sql)

    opts = cert_info.get('opt', ['CC'])
    return_code = 1
    err_msg = ''

    try:
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_value)
        except Exception as e:
            print(e)
            err_msg = 'Certificate content is illegal!'
            assert False

        subject = cert.get_subject()
        issued_to = subject.CN

        end_time = cert.get_notAfter()  # 结束时间
        end_time = end_time.decode()
        end_time = str_to_datetime(end_time, _format='%Y%m%d%H%M%SZ')

        start_time = cert.get_notBefore()  # 开始时间
        start_time = start_time.decode()
        start_time = str_to_datetime(start_time, _format='%Y%m%d%H%M%SZ')

        search_sql = {
            'cert_name': cert_name
        }

        if is_update:

            check_obj = await cert_db.find_one(search_sql)
            if not check_obj:
                err_msg = 'Certificate does not exist!'
                assert False


            update_name = '%s|%s|%s' % (cert_name, 'bak', str(int(time.time())))
            update_doc = {
                'status': 5,
                'update_name': update_name,
                'create_time': datetime.datetime.now(),
            }

            await cert_db.update_one(search_sql, {'$set': update_doc})

            cert_name = update_name
        else:
            check_obj = await cert_db.find_one(search_sql)
            if check_obj:
                err_msg = 'Certificate is already exist!'
                assert False

        cert_doc = {
            'cert_name': cert_name,
            'cert': cert_value,
            'key': key_value,
            'start_time': start_time,
            'end_time': end_time,
            'email': email,
            'period': period,
            'remark': remark,
            'cert_from': cert_from,
            'status': 0,
            'create_time': datetime.datetime.now(),
            'user_id': user_doc.get('user_id'),
            'username': username,
            'issued_to': issued_to,
            'opt_username': opt_username,
            'opts': opts
        }
        await cert_db.insert_one(cert_doc)

        args = {
            'user_doc': user_doc,
            'cert_db': cert_db,
            'cert_name': cert_name,
            'cert': cert_value,
            'key': key_value,
            'email': email,
            'period': period

        }

        result = await ExternalAPI.create_cert(opts, args)

        for opt in opts:
            if not result[opt][0]:
                msg = 'opt %s error %s %s' % (opt, cert_name, result[opt][1])
                err_msg = result[opt][1]
                logger.info(msg)
                assert False

        return_code = 0
    except AssertionError:
        pass

    except Exception as e:
        print(e)
        err_msg = e


    res = {
        'err_msg': err_msg,
        'return_code': return_code
    }
    return json(res)


@base_bp.route("/internal/ssl_cert_delete/", methods=['POST'])
async def ssl_cert_delete(request):
    """证书上传"""
    mongodb = request.app.M
    cert_db = mongodb.cert
    user_db = mongodb.user_profile

    cert_info = request.json

    cert_name = cert_info.get('cert_name', '')
    user_id = cert_info.get('user_id', '')

    user_search_sql = {
        'user_id': user_id
    }
    user_doc = await user_db.find_one(user_search_sql)
    opts = cert_info.get('opt', ['CC'])

    cert_search_sql = {
        'cert_name': cert_name,
        'user_id': user_id
    }

    cert_doc = await cert_db.find_one(cert_search_sql)

    err_msg = ''
    try:
        args = {
            'cert_doc': cert_doc,
            'user_doc': user_doc,
        }

        # result = await ExternalAPI.delete_cert(opts, args)
        #
        # for opt in opts:
        #     if not result[opt][0]:
        #         msg = 'opt %s error %s %s' % (opt, cert_name, result[opt][1])
        #         err_msg = result[opt][1]
        #         logger.info(msg)
        #         assert False

        update_doc = {
            'status': 4
        }

        obj = await cert_db.update_one(cert_search_sql, {'$set': update_doc})
        if obj:
            return_code = 0
        else:
            err_msg = 'Certificate does not exist!'
            assert False
    except AssertionError:
        pass

    res = {
        'err_msg': err_msg,
        'return_code': return_code
    }

    return json(res)


@base_bp.route("/internal/ssl_cert_query/", methods=['POST'])
async def ssl_cert_query(request):
    """证书列表"""
    mongodb = request.app.M
    cert_db = mongodb.cert

    cert_info = request.json

    search_sql = dict()

    cert_name = cert_info.get('cert_name', '')
    user_id = cert_info.get('user_id', '')
    status = cert_info.get('status', [])

    if cert_name:
        search_sql['cert_name'] = cert_name

    if status:
        search_sql['status'] = {'$in': status}

    if user_id:
        search_sql['user_id'] = user_id

    res = {}
    return_code = 1
    cert_list = []
    try:
        async for cert in cert_db.find(search_sql):
            cert_name = cert.get('cert_name', '')
            if 'bak' in cert_name:
                continue

            end_time = cert.get('end_time')
            end_time = datetime_to_str(end_time, _format='%Y-%m-%d %H:%M')

            start_time = cert.get('start_time')
            start_time = datetime_to_str(start_time, _format='%Y-%m-%d %H:%M')

            create_time = cert.get('create_time')
            create_time = datetime_to_str(create_time, _format='%Y-%m-%d %H:%M')


            username = cert.get('username', '')
            cert_from = cert.get('cert_from', '')
            status = cert.get('status', '')
            user_id = cert.get('user_id', '')
            issued_to = cert.get('issued_to', '')

            cert_dict = {
                'cert_name': cert_name,
                'user_id': user_id,
                'username': username,
                'cert_from': cert_from,
                'start_time': start_time,
                'end_time': end_time,
                'create_time': create_time,
                'issued_to': issued_to,
                'status': status
            }

            cert_list.append(cert_dict)


        return_code = 0
    except Exception as e:
        print(e)

    res['return_code'] = return_code
    res['cert_list'] = cert_list

    return json(res)


@base_bp.route("/internal/ssl_cert_detail/", methods=['POST'])
async def ssl_cert_detail(request):
    """证书详情"""
    mongodb = request.app.M
    cert_db = mongodb.cert
    cert_log_db = mongodb.cert_opt_log
    domain_db = mongodb.domain

    cert_info = request.json

    cert_name = cert_info.get('cert_name', '')
    user_id = cert_info.get('user_id', '')

    search_sql = {
        'cert_name': cert_name,
        'user_id': user_id
    }
    res = {}
    err_msg = ''
    return_code = 1
    cert_detail = {}
    try:
        cert = await cert_db.find_one(search_sql)
        if not cert:
            err_msg = 'Certificate does not exist!'
            assert False

        end_time = cert.get('end_time')
        end_time = datetime_to_str(end_time, _format='%Y-%m-%d %H:%M')

        start_time = cert.get('start_time')
        start_time = datetime_to_str(start_time, _format='%Y-%m-%d %H:%M')

        cert_name = cert.get('cert_name', '')
        username = cert.get('username', '')
        cert_from = cert.get('cert_from', '')
        status = cert.get('status', 0)
        remark = cert.get('remark', '')

        period = cert.get('period', 0)
        email = cert.get('email', '')

        issued_to = cert.get('issued_to', '')
        # issued_to = '*.chinacache.com'
        if '*' in issued_to:
            _, check_str = issued_to.split('*')
        else:
            check_str = issued_to

        search_sql = {'domain': {'$regex': check_str}}

        relation_list = []
        check_domain = []
        async for d in domain_db.find(search_sql).sort([('protocol', -1)]):

            domain = d.get('domain', '')

            if domain not in check_domain:
                cdn_opt = d.get('cdn', [])
                if not cdn_opt:
                    continue

                domain_status = await get_domain_status(
                    domain, cdn_opt, mongodb)

                domain_dict = {
                    'domain': d.get('domain', ''),
                    'status': domain_status
                }
                relation_list.append(domain_dict)

                check_domain.append(domain)

        log_search_sql = {
            'cert_name': cert_name
        }

        log_list = []
        async for l in cert_log_db.find(log_search_sql):
            l.pop('_id')
            log_list.append(l)


        cert_detail = {
            'end_time': end_time,
            'start_time': start_time,
            'cert_name': cert_name,
            'username': username,
            'cert_from': cert_from,
            'status': status,
            'remark': remark,
            'period': period,
            'email': email,
            'relation_list': relation_list,
            'log_list': log_list
        }

        return_code = 0
    except AssertionError:
        pass


    res['return_code'] = return_code
    res['cert_detail'] = cert_detail
    res['err_msg'] = err_msg

    return json(res)


@base_bp.route("/internal/domain_cc_conf/", methods=['POST'])
async def domain_cc_conf(request):
    """证书详情"""
    from fuse_api.externtal_api.cc_api import CCAPI
    mongodb = request.app.M
    cert_db = mongodb.cert
    domain_db = mongodb.domain
    user_db = mongodb.user_profile

    task_info = request.json

    user_id = task_info.get('user_id', '')
    domain = task_info.get('domain', '')
    protocol = task_info.get('protocol', '')

    res = {}

    try:
        channel = '%s://%s' % (protocol, domain)
        search_sql = {
            'user_id': user_id,
        }
        user_doc = await user_db.find_one(search_sql)
        print(user_doc)

        cms_username = user_doc.get('cms_username')

        cc_conf = await CCAPI.get_channel_conf(channel, cms_username)

        res.update(cc_conf)

        return_code = 0
    except AssertionError:
        pass


    res['return_code'] = return_code

    return json(res)
