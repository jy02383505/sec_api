
from fuse_api.externtal_api.base_api import API


async def shell(funcs, kwargs):
    try:
        ret = await funcs(kwargs)
        return ret
    except Exception as e:
        return e


class ExternalAPI(object):
    """融合API"""

    @staticmethod
    async def call_api(opts, action, args):
        """调用api"""
        result = {}

        opt_result_list = []
        opt_list = []
        for opt in opts:
            obj = getattr(API, opt, None)
            if obj:
                handel = getattr(obj, action, None)
                if handel:
                    opt_result = await shell(handel, args)
                    opt_result_list.append(opt_result)
                    opt_list.append(opt)
                else:
                    res_str = (
                        "operator: {} ,action: {} is not support!"
                    ).format(opt, action)
                    result[opt] = [0, res_str]
            else:
                res_str = "operator: {} is not support!".format(opt)
                result[opt] = [0, res_str]
        else:
            if opt_list and opt_result_list:
                for i in zip(opt_list, opt_result_list):
                    the_opt = i[0]
                    result_status, result_value = i[1]
                    result[the_opt] = [result_status, result_value]

        return result

    @staticmethod
    async def test(opts, args):
        """测试接口"""
        result = await ExternalAPI.call_api(opts, "test", args)

        print(result)

        return result

    @staticmethod
    async def create_domain(opts, args):
        """添加域名"""
        result = await ExternalAPI.call_api(opts, "create_domain", args)
        return result

    @staticmethod
    async def edit_domain(opts, args):
        """添加域名"""
        result = await ExternalAPI.call_api(opts, "edit_domain", args)
        return result

    @staticmethod
    async def sync_domain_conf(opts, args):
        """查询域名配置"""
        result = await ExternalAPI.call_api(opts, "sync_domain_conf", args)
        return result

    @staticmethod
    async def domain_flux(opts, args):
        """域名计费数据"""
        result = await ExternalAPI.call_api(opts, "domain_flux", args)
        return result
    
    @staticmethod
    async def domain_request(opts, args):
        """域名请求量"""
        result = await ExternalAPI.call_api(opts, "domain_request", args)
        return result

    @staticmethod
    async def domain_status_code(opts, args):
        """域名状态码"""
        result = await ExternalAPI.call_api(opts, "domain_status_code", args)
        return result

    @staticmethod
    async def domain_log(opts, args):
        """域名日志"""
        result = await ExternalAPI.call_api(opts, "domain_log", args)
        return result

    @staticmethod
    async def create_cert(opts, args):
        """证书添加"""
        result = await ExternalAPI.call_api(opts, "create_cert", args)
        return result

    @staticmethod
    async def delete_cert(opts, args):
        """证书删除"""
        result = await ExternalAPI.call_api(opts, "delete_cert", args)
        return result

    @staticmethod
    async def disable_domain(opts, args):
        """域名下线"""
        result = await ExternalAPI.call_api(opts, "disable_domain", args)
        return result

    @staticmethod
    async def active_domain(opts, args):
        """域名激活"""
        result = await ExternalAPI.call_api(opts, "active_domain", args)
        return result

    @staticmethod
    async def domain_flux_batch(opts, args):
        """域名流量批量请求"""
        result = await ExternalAPI.call_api(opts, "domain_flux_batch", args)
        return result

    @staticmethod
    async def domain_status_code_batch(opts, args):
        """域名状态吗批量请求"""
        result = await ExternalAPI.call_api(
            opts, "domain_status_code_batch", args)
        return result







