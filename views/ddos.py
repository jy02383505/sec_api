#!/usr/bin/env python
from sanic.log import logger
from sanic import Blueprint
from sanic.response import json as J
from sanic.response import stream


ddos_bp = Blueprint('ccddos', url_prefix='sec/ccddos')

@ddos_bp.route('/conf', methods=['GET', 'POST'])
async def conf(request):
    filename = request.args.get('filename', 'forReading.txt')
    with open(filename) as f:
        content = f.read()
    logger.info(f'conf filename: {filename}|| content: {content}')

    async def streaming(response):
        await response.write(content)
    return stream(streaming)
    # return J({'json': request.json, 'args': request.args, 'query_string': request.query_string})


@ddos_bp.route('/alarm', methods=['GET', 'POST'])
async def alarm(request):
    logger.info(f'alarm data: {request.json}')
    return J({"status": "ok"})