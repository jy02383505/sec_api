#!/usr/bin/python
# -*- coding: UTF-8 -*-
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from datetime import datetime
from datetime import timedelta
import pymongo
import time


class ES(object):
    es = Elasticsearch(['223.202.202.52:9200'], http_auth=('elastic', 'Ro4botp1aspBeLS'), timeout=300)
    interval = 60  # 检查一分钟内的数据
    start_time_point = 240  # 检查time_point前120秒的数据
    dburl = "mongodb://superAdmin:admin_Wlk@223.202.203.164:28001/"
    client = pymongo.MongoClient(dburl)
    db = client.realtimemonitoringtest

    def __init__(self, timestamp):
        self.toTimeStamp = timestamp - self.start_time_point
        self.fromTimeStamp = self.toTimeStamp - self.interval

    def get_index(self, name):
        try:
            lostashindextimestamp = int(self.toTimeStamp)
            date_obj = datetime.fromtimestamp(lostashindextimestamp) - timedelta(hours=8)
            # date_obj = date_obj - timedelta(hours=8)
            dt = date_obj.strftime("%Y.%m.%d.%H")
        except Exception as e:
            dt = '*'
        return '%s%s' % (name, dt)

    def get_attack_data(self):
        logstashindex = self.get_index('domainip-')
        print(logstashindex)
        filt = Q("match", msecRegion=self.toTimeStamp) & Q("range", **{
            "attackCount461": {
                "gt": 0
            }
        })
        s = Search(using=self.es, index=logstashindex).query(filt)
        s.aggs.bucket('terms_domain', 'terms', field='domain.keyword', size=100000)
        s.aggs['terms_domain'].bucket('terms_area', 'terms', field='address.keyword', size=100000)
        s.aggs['terms_domain']['terms_area'].bucket('terms_requestIp', 'terms', field='requestIp.keyword', size=10000)
        # s.aggs['terms_domain']['terms_area']['terms_requestIp'].bucket("term_total_461", "terms", field="attackCount461"
        #   , order={"term_total_461": "asc"}).metric("term_total_461", "sum", field="attackCount461")

        s.aggs['terms_domain']['terms_area']['terms_requestIp'].metric('term_total_461', 'sum',
                                                                                     field='attackCount461')

        total = 0
        for x in range(1, 4):
            total = s.count()
            if total != 0:
                break
        print("total:   ", total)
        if total == 0:
            print("kafka domain_ip is error, " + str(self.fromTimeStamp))
        response = s.execute()
        return response.aggregations.terms_domain.buckets

    def add_mongo(self, table, insert_data):
        self.db[table].insert_many(insert_data)


if __name__ == '__main__':
    try:
        # time_point = 1575942900
        time_point = time.mktime(datetime.now().replace(second=0, microsecond=0).timetuple())
        print(time_point)
        a = ES(time_point)
        result_data = a.get_attack_data()
        mongo_data_list = []
        for domain_data in result_data:
            domain_name = domain_data.key
            for area_data in domain_data.terms_area.buckets:
                area = area_data.key
                for ip_data in area_data.terms_requestIp.buckets:
                    ip = ip_data.key
                    term_total_461 = ip_data.term_total_461.value
                    print(domain_name, area, ip, term_total_461)
                    mongo_data_list.append({
                        "domain": domain_name,
                        "msecRegion": a.toTimeStamp,
                        "ip": ip,
                        "area": area,
                        "term_total_461": term_total_461
                    })
        a.add_mongo("auth_center_ip", mongo_data_list)

    except Exception as e:
        print(e)