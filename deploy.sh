#!/usr/bin/env bash

sudo yum -y install python-devel mysql-devel libffi-devel zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel libpcap-devel xz-devel git gcc
yum install -y mariadb mariadb-server
yum install -y bind-utils psmisc
rpm -ivh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
yum install -y nginx
systemctl start mariadb
systemctl enable mariadb
mysql_secure_installation

#
# [mysqld]
# character-set-server=utf8
#

curl https://pyenv.run | bash
echo -e '''export PATH="/root/.pyenv/bin:$PATH"\neval "$(pyenv init -)"\neval "$(pyenv virtualenv-init -)"''' >>/root/.bashrc
source /root/.bashrc
pyenv install 3.8.2
pyenv virtualenv 3.8.2 dnslog
~/.pyenv/versions/dnslog/bin/pip3  install -r ./requirements.txt
~/.pyenv/versions/dnslog/bin/python manage.py makemigrations logview
~/.pyenv/versions/dnslog/bin/python manage.py migrate
~/.pyenv/versions/dnslog/bin/python manage.py collectstatic
~/.pyenv/versions/dnslog/bin/gunicorn --workers 5 --bind 127.0.0.1:8000 dnslog.wsgi:application --daemon
nohup ~/.pyenv/versions/3.8.2/envs/dnslog/bin/python3.8 ./zoneresolver.py &
cp dnslog_nginx.conf /etc/nginx/conf.d/
setsebool httpd_can_network_connect on
setenforce permissive
systemctl restart nginx
timedatectl set-timezone Asia/Shanghai