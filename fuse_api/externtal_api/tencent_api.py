

class TencentAPI(object):

    def __init__(self, domain):
        self.domain = domain

    @staticmethod
    async def test(args):
        print(66666666666666)
        print('tencent test', args)

        return 1, 'success'

    @staticmethod
    async def create_cert(args):
        print('6ggggggggggggggggggggggggggg')
        cert_name = args.get('cert_name', '')

        cert_db = args.get('cert_db')

        search_sql = {
            'cert_name': cert_name,
        }
        cert_info = await cert_db.find_one(search_sql)

        send_info = cert_info.get('send_info', {})
        send_info.update({'TENCENT': 1})

        update_doc = {
            'send_info': send_info
        }

        await cert_db.update_one(search_sql, {'$set': update_doc})

        return True, {}
