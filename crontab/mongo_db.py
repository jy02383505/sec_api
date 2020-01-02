import pymongo

from config import mongo_config


def conn_domain_mongo():
    """domain db"""
    conn = pymongo.MongoClient(mongo_config)
    domain_db = conn['SEC_API'].domain
    return domain_db


def conn_cc_domain_task_mongo():
    """cc domain task db"""
    conn = pymongo.MongoClient(mongo_config)
    task_db = conn['SEC_API'].CC_CDN_domain_info
    return task_db


def conn_domain_cname_mongo():
    """domain cname db"""
    conn = pymongo.MongoClient(mongo_config)
    domain_cname_db = conn['SEC_API'].domain_cname
    return domain_cname_db


def refresh_task_db():
    """连接刷新任务记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    refresh_task = conn_db.refresh_task

    return refresh_task


def refresh_log_db():
    """连接刷新日志记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    refresh_log = conn_db.refresh_log

    return refresh_log


def preload_task_db():
    """连接预热任务记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    preload_task = conn_db.preload_task

    return preload_task


def preload_log_db():
    """连接预热日志记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    preload_log = conn_db.preload_log

    return preload_log


def cert_db():
    """连接证书记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    cert = conn_db.cert

    return cert


def cert_opt_db():
    """连接证书操作记录记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    cert_opt_log = conn_db.cert_opt_log

    return cert_opt_log


def conn_mongo_nsq_err_log():
    """连接nsq错误日志记录"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    nsq_err_log = conn_db.nsq_err_log

    return nsq_err_log


def conn_user_db():
    """连接user db"""
    conn = pymongo.MongoClient(mongo_config)
    conn_db = conn['SEC_API']
    user_profile = conn_db.user_profile
    return user_profile



