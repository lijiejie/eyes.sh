#! /usr/bin/env sh
set -e

python /dnslog/manage.py makemigrations logview
python /dnslog/manage.py migrate
python /dnslog/manage.py collectstatic --noinput

# Run nginx
nginx_count=`ps aux|grep nginx|grep -v grep|wc -l`
if [ $nginx_count -eq 0 ]; then
    nginx -g 'daemon off;' &
fi

# Run zoneresolver.py
zoneresolver_count=`ps aux|grep zoneresolver|grep -v grep|wc -l`
if [ $zoneresolver_count -eq 0 ]; then
    python /dnslog/zoneresolver.py &
fi

# Run gunicorn
gunicorn_count=`ps aux|grep gunicorn|grep -v grep|wc -l`
if [ $gunicorn_count -eq 0 ]; then
    gunicorn --workers 5 --bind 0.0.0.0:8000 dnslog.wsgi:application --daemon
fi

exec "$@"