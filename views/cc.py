#!/usr/bin/env python
import re
import sys
import time
import logging
from config import ES_HOST
from sanic import Blueprint
from sanic.log import logger
import datetime
from sanic.response import html
from sanic.response import text, json
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from jinja2 import Environment, PackageLoader, select_autoescape


log = logging.getLogger(__name__)

cc_bp = Blueprint('cc', url_prefix='cc')
# 开启异步特性  要求3.6+
enable_async = sys.version_info >= (3, 6)

env = Environment(
    loader=PackageLoader('views.cc', '../templates'),
    autoescape=select_autoescape(['html', 'xml', 'tpl']),
    enable_async=enable_async)


async def template(tpl, **kwargs):
    template = env.get_template(tpl)
    rendered_template = await template.render_async(**kwargs)
    return html(rendered_template)


@cc_bp.route("/check/es/", methods=['POST'])
async def check_es(request):
    """检测es链接是否正常"""
    domain_name = request.json.get("domain")
    time_out = 300
    try:
        es = Elasticsearch(ES_HOST[0], http_auth=(ES_HOST[1], ES_HOST[2]), timeout=time_out)
        time_point = time.mktime(datetime.datetime.now().replace(second=0, microsecond=0).timetuple())
        lostashindextimestamp = int(time_point - 300)
        date_obj = datetime.datetime.fromtimestamp(lostashindextimestamp) - datetime.timedelta(hours=8)
        logstashindex = '%s%s' % ('domainip-', date_obj.strftime("%Y.%m.%d.%H"))
        filt = Q("match", msecRegion=lostashindextimestamp) & Q("match", domain=domain_name)
        s = Search(using=es, index=logstashindex).query(filt)
        response = s.count()
        return_code = 0
        if response > 0:
            result = 0  # 已经配置es
        else:
            result = 1  # 未配置es
    except Exception as e:
        logger.error(f'check es: {e}')
        return_code = -1
        result = -1   # 系统错误
    ret = {"es_stat": result, "return_code": return_code}
    return json(ret)


@cc_bp.route("/config/domain_config/", methods=['POST'])
async def get_domain_config(request):
    """获取黑灰名单阈值配置"""
    mongodb = request.app.CCM
    alarm_trigger_db = mongodb.alarm_trigger
    check_trigger_db = mongodb.check_trigger
    domain_info = request.json
    domain = domain_info.get("domain")
    return_dict = {"config_list": [], "return_code": 0, "message": ""}
    try:
        data_list = {"foreign_static": {}, "foreign_dynamic": {}, "china_dynamic": {}, "china_static": {}}
        alarm_data_list = await query_alarm_trigger(alarm_trigger_db, domain)
        check_data_list = await query_check_trigger(check_trigger_db, domain)

        for alarm_data in alarm_data_list:
            alarm_area = alarm_data.get("area")
            alarm_resuest_type = alarm_data.get("request_type")
            switch_stat = alarm_data.get("switch_stat")
            for check_data in check_data_list:
                check_area = check_data.get("area")
                check_request_type = check_data.get("request_type")
                identiy = check_data.get("identiy")
                ip_check = check_data.get("IpCheck")
                if alarm_area == check_area and alarm_area == 1 and \
                        alarm_resuest_type == check_request_type and alarm_resuest_type == 1:
                        await set_data_obj("foreign_static", alarm_data, check_data, data_list, identiy, ip_check, switch_stat)
                if alarm_area == check_area and alarm_area == 1 and \
                        alarm_resuest_type == check_request_type and alarm_resuest_type == 0:
                        await set_data_obj("foreign_dynamic", alarm_data, check_data, data_list, identiy, ip_check,
                                       switch_stat)
                if alarm_area == check_area and alarm_area == 0 and \
                        alarm_resuest_type == check_request_type and alarm_resuest_type == 1:
                        await set_data_obj("china_static", alarm_data, check_data, data_list, identiy, ip_check,
                                       switch_stat)
                if alarm_area == check_area and alarm_area == 0 and \
                        alarm_resuest_type == check_request_type and alarm_resuest_type == 0:
                        await set_data_obj("china_dynamic", alarm_data, check_data, data_list, identiy, ip_check,
                                       switch_stat)
    except Exception as e:
        logger.error(f'get domain config query defult error: {e}')
        return_dict['message'] = f'get_ip_list[query defult error.]'
        return_dict['return_code'] = -1
    return_dict['config_list'] = str(data_list)
    return json(return_dict)


async def set_data_obj(obj_name, alarm_data, check_data, data_list, identiy, ip_check, switch_stat):
    """构建返回结果数据对象"""
    data_list[obj_name].setdefault(str(identiy), dict(alarm_data, **check_data))
    data_list[obj_name].setdefault("ip_check", ip_check)
    data_list[obj_name].setdefault("switch_stat", switch_stat)


@cc_bp.route("/update/update_domain_config/", methods=['POST'])
async def update_domain_config(request):
    """修改域名阈值配置 根据域名及国内海外条件"""
    mongodb = request.app.CCM
    check_trigger_db = mongodb.check_trigger
    alarm_trigger_db = mongodb.alarm_trigger
    request_body = request.json
    update_result = "success"
    return_code = 0
    try:
        domain_list = await analysis_po_obj(request_body)
        for domain_info in domain_list:
            await update_alarm_trigger(alarm_trigger_db, domain_info)
            await update_check_trigger(check_trigger_db, domain_info)
    except Exception as e:
        return_code = -1
        update_result = "error"
        logger.error(f'update_domain_config: {e}')
    ret = {
        "update_result": update_result,
        "return_code": return_code
    }
    return json(ret)


@cc_bp.route("/config/warn_config/", methods=['POST'])
async def get_warn_config(request):
    """获取告警阈值配置"""
    mongodb = request.app.CCM
    check_trigger_db = mongodb.check_trigger
    domain_info = request.json
    domain = domain_info.get("domain")
    data_list = {"domain_warn": {}}
    check_data_list = await query_check_trigger(check_trigger_db, domain)
    for check_data in check_data_list:
        if data_list["domain_warn"]:
            continue
        else:
            data_list["domain_warn"] = check_data

    ret = {"config_list": str(data_list)}
    return json(ret)


@cc_bp.route("/update/update_warn_config/", methods=['POST'])
async def update_warn_config(request):
    """修改域名告警配置"""
    mongodb = request.app.CCM
    check_trigger_db = mongodb.check_trigger
    domain_info = request.json
    check_result = await update_check_trigger(check_trigger_db, domain_info)
    update_config = "success"
    if check_result:
        update_config = "error"
    return json({"update_config": update_config})


async def analysis_po_obj(domain_list):
    """解析po对象"""
    return_data_list = []
    for key in domain_list:
        if key == "foreign_static":
            area = 1
            request_type = 0
        if key == "foreign_dynamic":
            area = 1
            request_type = 1
        if key == "china_dynamic":
            area = 0
            request_type = 1
        if key == "china_static":
            area = 0
            request_type = 0

        po_conf = domain_list[key]
        switch_stat = ""
        ip_check = ""
        if "switch_stat" in po_conf.keys():
            switch_stat = po_conf.get("switch_stat")
        if "ip_check" in po_conf.keys():
            ip_check = po_conf.get("ip_check")
        if "0" in po_conf.keys():
            black_data = po_conf.get("0")
            black_data["switch_stat"] = switch_stat
            black_data["IpCheck"] = ip_check
            black_data["area"] = area
            black_data["request_type"] = request_type
            return_data_list.append(black_data)
        if "1" in po_conf.keys():
            grey_data = po_conf.get("1")
            grey_data["switch_stat"] = switch_stat
            grey_data["IpCheck"] = ip_check
            grey_data["area"] = area
            grey_data["request_type"] = request_type
            return_data_list.append(grey_data)
    return return_data_list


async def update_check_trigger(check_trigger_db, domain_info):
    """check修改"""
    query_sql = {}
    update_check_sql = {}
    if "domain" in domain_info:
        query_sql["domain"] = domain_info.get("domain")
    if "area" in domain_info:
        query_sql["area"] = domain_info.get("area")
    if "request_type" in domain_info:
        query_sql["request_type"] = domain_info.get("request_type")
    if "identiy" in domain_info:
        query_sql["identiy"] = domain_info.get("identiy")
    if "IpTotal" in domain_info:
        update_check_sql["IpTotal"] = domain_info.get("IpTotal")
    if "IpCheck" in domain_info:
        update_check_sql["IpCheck"] = domain_info.get("IpCheck")
    if "refer" in domain_info:
        update_check_sql["refer"] = domain_info.get("refer")
    if "range" in domain_info:
        update_check_sql["range"] = domain_info.get("range")
    if "cache" in domain_info:
        update_check_sql["cache"] = domain_info.get("cache")
    if "IpProportion" in domain_info:
        update_check_sql["IpProportion"] = domain_info.get("IpProportion")
    if "TotalIpSuddenrise" in domain_info:
        update_check_sql["TotalIpSuddenrise"] = domain_info.get("TotalIpSuddenrise")
    if "200SuddenDrop" in domain_info:
        update_check_sql["200SuddenDrop"] = domain_info.get("200SuddenDrop")
    if "502Suddenrise" in domain_info:
        update_check_sql["502Suddenrise"] = domain_info.get("502Suddenrise")
    if "missSuddenrise" in domain_info:
        update_check_sql["missSuddenrise"] = domain_info.get("missSuddenrise")
    await check_trigger_db.update_many(query_sql, {'$set': update_check_sql})


async def update_alarm_trigger(alarm_trigger_db, domain_info):
    """alarm修改"""
    query_sql = {}
    update_alerm_sql = {}
    if "domain" in domain_info:
        query_sql["domain"] = domain_info.get("domain")
    if "area" in domain_info:
        query_sql["area"] = domain_info.get("area")
    if "request_type" in domain_info:
        query_sql["request_type"] = domain_info.get("request_type")
    if "auto_black" in domain_info:
        update_alerm_sql["auto_black"] = domain_info.get("auto_black")
    if "warn" in domain_info:
        update_alerm_sql["warn"] = domain_info.get("warn")
    if "auto_grey" in domain_info:
        update_alerm_sql["auto_grey"] = domain_info.get("auto_grey")
    if "grey" in domain_info:
        update_alerm_sql["grey"] = domain_info.get("grey")
    if "black" in domain_info:
        update_alerm_sql["black"] = domain_info.get("black")
    if "switch_stat" in domain_info:
        update_alerm_sql["switch_stat"] = domain_info.get("switch_stat")
    if "challenge_type" in domain_info:
        update_alerm_sql['challenge_type'] = domain_info.get("challenge_type")
    if "banned_time" in domain_info:
        update_alerm_sql['banned_time'] = domain_info.get("banned_time")
    if "challenge_time" in domain_info:
        update_alerm_sql['challenge_time'] = domain_info.get("challenge_time")
    await alarm_trigger_db.update_many(query_sql, {'$set': update_alerm_sql})


async def query_alarm_trigger(alarm_trigger_db, domain):
    """alarm查询"""
    data_list = []
    domain_sql = {}
    domain_sql['domain'] = domain
    async for tmpdata in alarm_trigger_db.find(domain_sql):
        data_list.append(tmpdata)
    if len(data_list) < 4:
        domain_sql['domain'] = "defult"
        data_list = []
        async for tmpdata in alarm_trigger_db.find(domain_sql):
            tmpdata["domain"] = domain
            # tmpdata["_id"] = ""
            tmpdata.pop("_id")
            data_list.append(tmpdata)
        await alarm_trigger_db.insert_many(data_list)
    return data_list


async def query_check_trigger(check_trigger_db, domain):
    """check查询"""
    domain_sql = {}
    domain_sql['domain'] = domain
    data_list = []
    async for tmpdata in check_trigger_db.find(domain_sql):
        data_list.append(tmpdata)
    if len(data_list) < 8:
        domain_sql['domain'] = "defult"
        data_list = []
        async for tmpdata in check_trigger_db.find(domain_sql):
            tmpdata["domain"] = domain
            data_list.append(tmpdata)
            tmpdata.pop("_id")
            # tmpdata["_id"] = ""
        await check_trigger_db.insert_many(data_list)
    return data_list


@cc_bp.route("/authCenter/TopIp/", methods=['POST'])
async def auth_center_top_ip(request):
    """中央鉴权Top10 ip"""
    return_code = 0
    data_list = []
    try:
        mongodb = request.app.CCM
        domain_info = request.json
        domain = domain_info.get("domain")
        start_time = domain_info.get("start_time")
        end_time = domain_info.get("end_time")
        if domain and start_time and end_time:
            query_condition = [
                {'$match': {'domain': domain, 'msecRegion': {'$gt': start_time, '$lt': end_time}}},
                {'$group': {'_id': {'ip': '$ip', 'area': '$area'}, 'term_total_461': {'$sum': '$term_total_461'}}},
                {'$sort': {'term_total_461': -1}}, {'$limit': 10}
            ]
            auth_center_ip = mongodb.auth_center_ip
            async for tmpdata in auth_center_ip.aggregate(query_condition):
                ip = tmpdata.get("_id").get("ip")
                area = tmpdata.get("_id").get("area")
                term_total_461 = tmpdata.get("term_total_461")
                data_list.append({
                    "ip": ip,
                    "area": area,
                    "term_total_461": term_total_461
                })
        else:
            return_code = 1  # 参数错误
    except Exception as e:
        return_code = -1
        logger.error(f'auth center top ip: {e}')
    ret = {
        "ip_list": str(data_list),
        "return_code": return_code
    }
    return json(ret)


@cc_bp.route("/ipList/get_ip_list/", methods=['POST'])
async def auth_center_top_ip(request):
    mongodb = request.app.CCM
    ip_list_db = mongodb.iplist
    domain_sql = {}
    return_dict = {'return_code': -1, 'message': '...'}
    domain_info = request.json
    domain = domain_info.get("domain")
    start_time = domain_info.get("start_time")
    end_time = domain_info.get("end_time")
    ip = domain_info.get("ip")
    country = domain_info.get("country")
    province = domain_info.get("province")
    city = domain_info.get("city")
    operator = domain_info.get("operator")
    challenge_type = domain_info.get("challenge_type")
    rule = domain_info.get("rule")
    reason = domain_info.get("reason")
    operator_name = domain_info.get("operator_name")
    area_sql_list = []
    if not domain:  # 域名
        domain_sql["domain"] = domain
        logger.error(f'getDomainStatus[dataError.] data: {domain_info}')
        return_dict['message'] = f'get_ip_list[paramError.] param: domain'
        return json(return_dict)
    if start_time:  # 开始时间
        domain_sql["start_time"] = start_time
    if end_time:  # 结束时间
        domain_sql["end_time"] = end_time
    if ip:  # ip
        domain_sql["ip"] = ip
    if country:  # 国家
        area_sql_list.append({"area": re.compile(country)})
    if province:  # 省份
        area_sql_list.append({"area": re.compile(province)})
    if city:  # 城市
        area_sql_list.append({"area": re.compile(city)})
    if operator:  # 运营商
        domain_sql["ip"] = ip
    if operator_name:  # 操作人
        domain_sql["ip"] = ip
    if challenge_type:  # 动作
        domain_sql["ip"] = ip
    if rule:  # 加灰规则
        domain_sql["ip"] = ip
    if reason:  # 加灰原因
        domain_sql["ip"] = ip

    async for tmpdata in ip_list_db.find(domain_sql):
        tmpdata["domain"] = domain