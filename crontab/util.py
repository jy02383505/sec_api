# coding=utf-8
"""
各个脚本使用的公共方法
"""
import time
import hashlib
import datetime


def datetime_to_str(date_time, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param date_time: datetime.datetime(2016, 1, 1, 0, 0, 0)
    :param _format: 时间格式
    :return: 2016-01-01 00：00：00
    """
    return date_time.strftime(_format)


def datetime_to_timestamp(date_time):
    """
    :param date_time: datetime.datetime(2016, 1, 1, 0, 0, 0)
    :return: 1451577600
    """
    return int(time.mktime(date_time.timetuple()))


def timestamp_to_datetime(timestamp):
    """
    :param timestamp: 1451577600
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    return datetime.datetime.fromtimestamp(timestamp)


def timestamp_to_str(timestamp, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param timestamp: 1451577600
    :param _format: 时间格式
    :return: 2016-01-01 00：00：00
    """
    return time.strftime(_format, time.localtime(timestamp))


def datetime_correction(_datetime, fix=5):
    """
    时间修正
    :param _datetime: 需要修正的时间datetime.datetime(2016, 1, 1, 0, 4, 0)
    :param fix: 修正系数
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    target_time = datetime.datetime(_datetime.year, _datetime.month,
                                    _datetime.day, _datetime.hour,
                                    _datetime.minute)

    if (target_time.minute % fix) != 0:
        sub = target_time.minute % fix
        target_time -= datetime.timedelta(minutes=sub)
    return target_time


def str_to_datetime(time_str, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param time_str: 2016-01-01 00：00：00
    :param _format: 时间格式
    :return: datetime.datetime(2016, 1, 1, 0, 0, 0)
    """
    temp_time = time.strptime(time_str, _format)
    result_datetime = datetime.datetime(*temp_time[:6])
    return result_datetime


def str_to_timestamp(time_str, _format='%Y-%m-%d %H:%M:%S'):
    """
    :param time_str: 2016-01-01 00：00：00
    :param _format: 时间格式
    :return: 123456789
    """
    temp_time = time.strptime(time_str, _format)
    result_datetime = datetime.datetime(*temp_time[:6])
    return int(time.mktime(result_datetime.timetuple()))


def get_time_list(start_time, end_time, _format='%Y-%m-%d %H:%M'):
    """获取时间范围内时间节点"""
    end_time += 300
    if _format == '%Y-%m-%d %H:00':
        step = 3600
    elif _format == '%Y-%m-%d 00:00':
        step = 3600 * 24
    else:
        step = 300

    def change(_format):
        def get_change(t):
            return timestamp_to_str(t, _format)
        return get_change

    real_change = change(_format)
    return map(real_change, range(start_time, end_time, step))


def get_day_list(date_time, fix=5):
    """获取颗粒时间列表"""
    num = 288
    day_list = []
    for i in range(0, num):
        day_list.append(date_time)
        date_time += datetime.timedelta(minutes=fix)

    return day_list


def get_time_nodes(start_time, end_time):
    """获取时间节点
    end_time, start_time 时间戳格式
    """
    start_time = timestamp_to_datetime(start_time)
    end_time = timestamp_to_datetime(end_time)
    sub_day = (end_time - start_time).days

    target_days = []
    for d in range(0, sub_day + 1):
        target_time = start_time + datetime.timedelta(days=d)
        target_time = target_time.strftime('%Y-%m-%d')
        target_days.append(target_time)

    time_nodes = []
    for time_str in target_days:
        day_start = str_to_datetime(time_str, _format='%Y-%m-%d')
        day_list = get_day_list(day_start)
        time_nodes.extend(day_list)

    return time_nodes


def get_md5_flag():
    """用时间生成md5标识"""
    hash_lib = hashlib.md5()
    sec_str = str(time.time())
    hash_lib.update(sec_str.encode())
    return hash_lib.hexdigest()


if __name__ == '__main__':
    print('test')