# config_file
import logging
# import aiotask_context as context

#---test env.add the contents below to /etc/hosts
## test QingSongYunAPI
# 139.219.109.56 https://api.qssec.com:6447/
# 139.219.109.56 api.qssec.com
QSURL = 'https://api.qssec.com:6447/'
QS_TOKEN = 'ce0028217fd7e774e3df5a36f7970b91'

#---product env
# QSURL = 'https://api.qssec.com'
# QS_TOKEN = 'd66a4ed68bfbd8ca8fa44a27a4e017'

# M_CONFIG = {
#     "host": '223.202.203.52',
#     "port":  27017,
#     "dbname":  'bermuda_s1',
#     "user":  'bermuda',
#     "passwd": 'bermuda_refresh',
# }

# M_CONFIG = {
#     "host": '223.202.202.15',
#     "port":  27012,
#     "dbname":  'SEC_API',
#     "user":  'superAdmin',
#     "passwd": 'admin_Wlk',
# }

M_CONFIG = 'mongodb://superAdmin:admin_Wlk@223.202.202.15:27010,223.202.202.15:27011,223.202.202.15:27012/'

R_CONFIG = {
    "host": '223.202.203.31',
    "port":  6379,
    "dbnum":   14,
    "password": 'bermuda_refresh',
}

DB_CONFIG = {
    "DB_HOST": '192.168.6.120',
    "PORT":  3306,
    "DB_NAME": 'fuse_nova',
    "DB_USER": 'root',
    "DB_PASS": '123456',
}

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8800,
    "debug": True,
    "ssl": None,  # SSLContext。
    "sock": None,  # 服务器接受连接的Socket。
    "worker": 4,  # 生成的工作进程数。
    # "loop":None,# asyncio兼容的事件循环。如果没有指定，Sanic会创建自己的事件循环。
    "protocol": "HttpProtocol",  # asyncio.protocol的子类。
    "access_log": True,
}


# class RequestIdFilter(logging.Filter):
#     def filter(self, record):
#         record.request_id = context.get('X-Request-ID')
#         return True


LOG_SETTINGS = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'default',
            # 'filters': ['requestid'],
        },
        'accessFile': {
            'class': 'logging.FileHandler',
            # 'filters': ['accessFilter'],
            'formatter': 'default',
            'filename': "logs/access.log"
        },
        'errorFile': {
            'class': 'logging.FileHandler',
            # 'filters': ['errorFilter'],
            'formatter': 'simple',
            'filename': "logs/err.log"
        },
    },
    # 'filters': {
    #     'requestid': {
    #         '()': RequestIdFilter,
    #     },
    # },
    'formatters': {
        'default': {
            'format': '%(asctime)s %(levelname)s %(name)s:%(lineno)d| %(message)s',
            # 'format': '%(asctime)s %(levelname)s %(name)s:%(lineno)d %(request_id)s | %(message)s',
        },
        'simple': {
            'format': '%(asctime)s - (%(name)s)[%(levelname)s]: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'access': {
            'format': '%(asctime)s - (%(name)s)[%(levelname)s][%(host)s]: ' +
            '%(request)s %(message)s %(status)d %(byte)d',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        }
    },
    'loggers': {
        '': {
            'level': 'DEBUG',
            'handlers': ['console', 'accessFile'],
            'propagate': True
        },
        # 'sanic': {
        #     'level': 'DEBUG',
        #     'handlers': ['console','accessFile'],
        #     'propagate': True
        # },
    }
}
