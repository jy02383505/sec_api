#!/bin/sh
# 使用方法：
# 1.cd到/var/www/sec_api
# 2.手动激活pipenv shell
# 3.使用./startup.sh start|stop|restart|status 即可完成快速操作sec服务
cd /var/www/sec_api


start_sec() {
    echo "sec_api is running ..."
    nohup python /var/www/sec_api/run.py &
}

stop_sec() {
    echo "`date  '+%F %T'` killing sec_api"
    # pid=`ps -eo pid,cmd|grep -v grep|grep sec|awk '{print $1}'`
    # pid=`ps aux|grep -v grep|grep "/var/www/sec_api/run.py"|awk '{print $2}'`
    pid=`ps aux|grep -v grep|grep "run.py"|awk '{print $2}'`
    echo kill $pid
    kill $pid
}

status_sec() {
    # ps aux|grep -v grep|grep "/var/www/sec_api/run.py" --color
    ps aux|grep -v grep|grep "run.py" --color
}


case "$1" in
    start)
        start_sec
    ;;  

    stop)
        stop_sec
    ;;  

    status)
        status_sec
    ;;  

    restart)
        stop_sec
        sleep 1
        start_sec
    ;;    

    *)
    echo "Usage: /startup.sh {[start|stop|restart|status]}"
        exit 1
    ;;
esac

exit 0