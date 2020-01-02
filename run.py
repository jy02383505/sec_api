# !/usr/bin/env python
import sys
import os
import asyncio
import uvloop
from sanic.response import text
from sanic import Sanic
from sanic.log import logger
from config import DEFAULT_CONFIG, LOG_SETTINGS, R_CONFIG, M_CONFIG, CC_M_CONFIG
import contextvars
import aioredis
from motor import motor_asyncio

from views import waf_bp, sec_bp, base_bp, cdn_bp, cc_bp, ddos_bp
from views.waf import ReqSender

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# sys.path.append('../')

# from config import CONFIG

# app.statics('/statics', CONFIG.BASE_DIR + '/statics')

app = Sanic(__name__, log_config=LOG_SETTINGS)

db_settings = {
    "REQUEST_TIMEOUT": 300,  # 60 seconds
    "RESPONSE_TIMEOUT": 300,  # 60 seconds
}
app.config.update(db_settings)
# app.config.from_pyfile("./config/config.py")


app.blueprint(sec_bp)
app.blueprint(waf_bp)
app.blueprint(base_bp)
app.blueprint(cdn_bp)
app.blueprint(cc_bp)
app.blueprint(ddos_bp)


# @app.middleware('request')
# async def set_request_id(request):
#     request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
#     context.set("X-Request-ID", request_id)

# 此处将路由 / 与视图函数 test 关联起来
@app.route("/")
async def test(request):
    logger.info('test[root request] hello world...')
    return text('Hello World!')


@app.listener('before_server_start')
def init(sanic, loop):

    # redisURI = 'redis://%s:%s/%s?encoding=utf-8' % (R_CONFIG['host'], R_CONFIG['port'], R_CONFIG['dbnum'])
    # sanic.R = loop.run_until_complete(aioredis.create_redis_pool(redisURI, password=R_CONFIG['password']))

    # mongoURI = 'mongodb://%s:%s@%s:%s/%s' % (M_CONFIG['user'], M_CONFIG['passwd'], M_CONFIG['host'], M_CONFIG['port'], M_CONFIG['dbname'])
    # client = motor_asyncio.AsyncIOMotorClient(mongoURI, io_loop=loop)
    # sanic.M = client[M_CONFIG['dbname']]

    sanic.M = motor_asyncio.AsyncIOMotorClient(M_CONFIG)["SEC_API"]
    sanic.QS = ReqSender(sanic.M)
    sanic.CCM = motor_asyncio.AsyncIOMotorClient(CC_M_CONFIG)["realtimemonitoringtest"]
    sanic.CCQS = ReqSender(sanic.CCM)


if __name__ == "__main__":
    app.run(host=DEFAULT_CONFIG["host"], port=DEFAULT_CONFIG["port"], debug=DEFAULT_CONFIG[
            "debug"], access_log=DEFAULT_CONFIG["access_log"], worker=DEFAULT_CONFIG["worker"])

    # asyncio.set_event_loop(uvloop.new_event_loop())
    # server = app.create_server(host="0.0.0.0", port=8000, return_asyncio_server=True)
    # loop = asyncio.get_event_loop()
    # loop.set_task_factory(context.task_factory)
    # task = asyncio.ensure_future(server)
    # try:
    #     loop.run_forever()
    # except:
    #     loop.stop()
