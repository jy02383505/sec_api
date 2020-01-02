# -*- coding:utf-8 -*-

from fuse_api.externtal_api.cc_api import CCAPI
from fuse_api.externtal_api.tencent_api import TencentAPI


class API(object):
    """API 集合"""
    CC = CCAPI
    TENCENT = TencentAPI

