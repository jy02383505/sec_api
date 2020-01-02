# coding=utf-8
import json
import requests


def test_link_api():
    """测试链接api"""

    host = "127.0.0.1:8800"

    request_url = '/sec/test/'

    body = {
        "domain": "www.test37.novacdn.com",
        "cname": "xxx"
    }

    headers = {
        "content-type": "application/json"
    }

    print(headers)

    url = 'http://%s%s' % (host, request_url)

    data = json.dumps(body)

    res = requests.post(url, data=data, headers=headers)
    print(res.text)
    print(res)


if __name__ == '__main__':
    test_link_api()
