FROM python:3.8

ENV TZ Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ADD . /dnslog
RUN pip install -r /dnslog/requirements.txt
RUN chmod +x /dnslog/docker-entrypoint.sh

WORKDIR /dnslog
EXPOSE 53

ENTRYPOINT ["/dnslog/docker-entrypoint.sh"]

# Install nginx
RUN apt update -y
RUN apt-get install -y \
		ca-certificates \
		nginx \
		gettext-base \
	&& rm -rf /var/lib/apt/lists/*

RUN ln -sf /dev/stdout /var/log/nginx/access.log \
	&& ln -sf /dev/stderr /var/log/nginx/error.log

RUN cp /dnslog/dnslog_nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]