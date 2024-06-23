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
# DROP DATABASE `dnslog`;
# CREATE DATABASE `dnslog` CHARACTER SET utf8 COLLATE utf8_general_ci;

curl https://pyenv.run | bash
echo -e '''export PATH="/root/.pyenv/bin:$PATH"\neval "$(pyenv init -)"\neval "$(pyenv virtualenv-init -)"''' >>/root/.bashrc
source /root/.bashrc
mkdir ~/.pyenv/cache
# For chinese user:
wget -P ~/.pyenv/cache/ https://registry.npmmirror.com/-/binary/python/3.8.2/Python-3.8.2.tar.xz
pyenv install 3.8.2
pyenv virtualenv 3.8.2 dnslog
~/.pyenv/versions/dnslog/bin/pip3  install -r ./requirements.txt
~/.pyenv/versions/dnslog/bin/python manage.py makemigrations logview
~/.pyenv/versions/dnslog/bin/python manage.py migrate
~/.pyenv/versions/dnslog/bin/python manage.py collectstatic
~/.pyenv/versions/dnslog/bin/gunicorn --workers 5 --bind 127.0.0.1:8000 dnslog.wsgi:application --daemon
nohup ~/.pyenv/versions/3.8.2/envs/dnslog/bin/python3.8 ./zoneresolver.py &
envsubst '$ADMIN_DOMAIN,$DNS_DOMAIN' < /dnslog/dnslog_nginx.conf > /etc/nginx/conf.d/default.conf
setsebool httpd_can_network_connect on
setenforce permissive
systemctl restart nginx
timedatectl set-timezone Asia/Shanghai
