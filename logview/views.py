# coding=utf-8

import hashlib
import json
import requests
import struct
import socket
import random
import string
import re
from django.utils import timezone
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator, InvalidPage, EmptyPage, PageNotAnInteger
from django import forms
from .models import User, WebLog, DNSLog, Config
from django.contrib.auth.models import User as SysUser
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.contrib.auth import logout
from django.utils.translation import gettext as _


def get_city_by_ip(ip):
    try:
        doc = requests.get('http://ip.ws.126.net/ipquery?ip=%s' % ip).text
        doc = doc[doc.find('var localAddress=')+17:].strip()
        doc = doc.replace('city', '"city"').replace('province', '"province"')
        _doc = json.loads(doc)
        city = _doc['province'] + ' ' + _doc['city']
    except Exception as e:
        city = ''
    return city


@csrf_exempt
def index(request):
    http_host = request.get_host().split(':')[0]
    if http_host in settings.ADMIN_DOMAIN:
        return redirect('/login')

    user_agent = request.META.get('HTTP_USER_AGENT') or ''
    user_agent = user_agent[:250]
    remote_addr = request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')
    path = http_host + request.get_full_path()
    path = path[:250]

    if not http_host.endswith(settings.DNS_DOMAIN):
        return HttpResponse("Server Gone", status=502)

    subdomain = http_host.replace(settings.DNS_DOMAIN, '')
    if subdomain:
        items = subdomain.split('.')
        if len(items) >= 2:
            user_domain = items[-2]
            user = User.objects.filter(user_domain=user_domain)
            if user:
                city = get_city_by_ip(remote_addr)
                request_headers = ''
                for key in request.META:
                    if key.startswith('REQUEST_') or key.startswith('HTTP_') or key.startswith('CONTENT_'):
                        request_headers += key + ': ' + str(request.META[key]) + '\n'

                if request.META.get('REQUEST_METHOD') == 'POST':
                    request_headers += '\n' + request.body.decode()

                weblog = WebLog(user=user[0], path=path, remote_addr=remote_addr,
                                user_agent=user_agent, city=city, headers=request_headers)
                weblog.save()
                if path.find('/rpb.png') >= 0:    # this is for AWVS Scanner
                    return HttpResponse('39a6ea3246b507782676a6d79812fa1d29e12e9c')
                return HttpResponse('OK')
    return HttpResponse('Failed')


class UserForm(forms.Form):
    username = forms.CharField(label='用户名', max_length=128)
    password = forms.CharField(label='密码', widget=forms.PasswordInput())


def do_login(request):
    userid = request.session.get('userid', None)
    if userid:
        return HttpResponseRedirect('/dns/')

    context = {'title': _('登录'), 'enable_register': 'yes', 'enable_create_random_user': 'yes'}
    c = Config.objects.filter(name='enable_register')
    if c and 'no' == c[0].value:
        context['enable_register'] = 'no'
    c = Config.objects.filter(name='enable_create_random_user')
    if c and 'no' == c[0].value:
        context['enable_create_random_user'] = 'no'

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = User.objects.filter(username=username)
        if user:
            user = user[0]
            if user.try_login_counter > 10 and (timezone.now() - user.last_try_login_time).seconds < 600:
                user.try_login_counter += 1
                user.save()
                context['error_msg'] = _('登录失败次数太多，锁定10分钟')
                return render(request, 'login.html', context)
            if user.password == hashlib.md5((password + username[:3] + '@dnslog').encode('utf-8')).hexdigest():
                request.session['userid'] = user.id
                request.session['username'] = user.username
                user.try_login_counter = 0
                user.login_ip = request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')
                user.save()
                return redirect('/dns/')
            else:
                user.try_login_counter += 1
                user.save()
        context['error_msg'] = _('用户名或密码错误')
        return render(request, 'login.html', context)

    if User.objects.count() < 1:
        return redirect('/register')
    context['error_msg'] = request.GET.get('msg', '')
    return render(request, 'login.html', context)


def random_id_login(request):
    c = Config.objects.filter(name='enable_create_random_user')
    if c and 'no' == c[0].value:
        return redirect('/login?msg=' + _('随机账号功能已关闭'))

    user_agent = request.META.get('HTTP_USER_AGENT').lower()
    if user_agent.find('bot') > 0 or user_agent.find('spider') > 0:
        return redirect('/login?msg=' + _('爬虫禁止登录'))

    user_ip = request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')
    if User.objects.filter(login_ip=user_ip).count() > 20:
        return redirect('/login?msg=' + _('随机账号超限，请注册登录'))
    for _ in range(30):
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        if not User.objects.filter(username=username):
            token = hashlib.md5((username + '@random_token').encode('utf-8')).hexdigest()[:8]
            user = User.objects.create(username=username, password='NO_LOGIN', email='', user_domain=username,
                                       token=token, try_login_counter=0, login_ip=user_ip, is_random_user=1)
            request.session['userid'] = user.id
            request.session['username'] = username
            return redirect('/dns/')
    return redirect('/login?msg=' + _('随机账号创建失败'))


def register(request):
    c = Config.objects.filter(name='enable_register')
    if c and 'no' == c[0].value:
        return redirect('/login?msg=' + _('注册功能已关闭'))
    username = request.POST.get('username', '')[:100]
    password = request.POST.get('password', '')[:100]
    email = request.POST.get('email', '')[:100]
    context = {'title': _('注册'), 'reg': 'true', 'error_msg': '',
               'username': username, 'password': password, 'email': email}
    if User.objects.count() < 1:
        context['init'] = 'true'

    if request.method == 'POST':
        if User.objects.filter(username=username):
            context['error_msg'] = _('无法创建该账号,已被占用')
            return render(request, 'login.html', context)
        else:
            m = re.match('[a-zA-Z0-9]+', username)
            if not m or len(m.group()) != len(username):
                context['error_msg'] = _('用户名只能包含字母或数字')
                return render(request, 'login.html', context)
            password = hashlib.md5((password + username[:3] + '@dnslog').encode('utf-8')).hexdigest()
            token = hashlib.md5((password + username[:3] + '@token').encode('utf-8')).hexdigest()[:8]
            user = User.objects.create(username=username, password=password,
                                       email=email, user_domain=username, token=token, try_login_counter=0)
            if context.get('init', ''):
                user.is_admin = 1
                SysUser.objects.create_user(username=username, email=email, password=password,
                                            is_staff=1, is_superuser=1)
            user.save()
            return redirect('/login?msg=' + _('注册成功,请登录以确保密码有效'))

    return render(request, 'login.html', context)


def do_logout(request):
    logout(request)
    return HttpResponseRedirect('/')


def get_page(p):
    try:
        page = int(p)
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    return page


def dns_view(request):
    return log_view(request, 'dns')


def dns_delete(request):
    userid = request.session.get('userid', None)
    if not userid:
        return redirect('/login')
    dns_id = request.GET.get("id")
    ip = request.GET.get("ip")
    domain = request.GET.get("domain")
    user = User.objects.filter(id=userid)[0]
    obj = DNSLog.objects.filter(user=user)
    if dns_id:
        obj = obj.filter(id=dns_id)
    if ip:
        obj = obj.filter(ip=ip)
    if domain:
        obj = obj.filter(host__icontains=domain)
    url = '/dns/?page=' + request.GET.get("page") if request.GET.get("page") else '/dns/?'
    if obj:
        if user.username != 'demo':
            obj.delete()
        return redirect(url+'&suc=' + _('删除成功'))
    else:
        if request.GET.get("domain"):
            url += "&domain=" + request.GET.get("domain")
        if request.GET.get("ip"):
            url += "&ip=" + request.GET.get("ip")
        return redirect(url+"&fail=" + _("删除失败"))


def web_delete(request):
    userid = request.session.get('userid', None)
    if not userid:
        return redirect('/login')
    web_id = request.GET.get("id")
    ip = request.GET.get("ip")
    path = request.GET.get("path")
    headers = request.GET.get("headers")
    user = User.objects.filter(id=userid)[0]
    obj = WebLog.objects.filter(user=user)
    if web_id:
        obj = obj.filter(id=web_id)
    if ip:
        obj = obj.filter(remote_addr=ip)
    if path:
        obj = obj.filter(path__icontains=path)
    if headers:
        obj = obj.filter(headers__icontains=headers)
    url = '/web/?page=' + request.GET.get("page") if request.GET.get("page") else '/web/?'
    if obj:
        if user.username != 'demo':
            obj.delete()
        return redirect(url+'&suc=' + _('删除成功'))
    else:
        if request.GET.get("domain"):
            url += "&domain=" + request.GET.get("domain")
        if request.GET.get("ip"):
            url += "&ip=" + request.GET.get("ip")
        return redirect(url+"&fail=" + _("删除失败"))


def web_view(request):
    return log_view(request, 'web')


def config_view(request):
    return log_view(request, 'config')


def rebind_view(request):
    return log_view(request, 'rebind')


def payloads_view(request):
    return log_view(request, 'payloads')


def log_view(request, type):
    userid = request.session.get('userid', None)
    if not userid:
        return redirect('/login')
    user = User.objects.filter(id=userid)[0]
    context = {}
    context['is_admin'] = user.is_admin
    context['type'] = type
    for var_name in ['domain', 'suc', 'fail', 'monitor', 'path', 'headers']:
        context[var_name] = request.GET.get(var_name, '')
    page = get_page(request.GET.get("page", 1))

    if type == 'dns':
        objects = DNSLog.objects.filter(user=user)
        if request.GET.get('ip'):
            objects = objects.filter(ip=request.GET.get('ip'))
        if request.GET.get('domain'):
            objects = objects.filter(host__icontains=request.GET.get('domain'))
        paginator = Paginator(objects.order_by('-id'), 10)
        try:
            logs = paginator.page(page)
        except(EmptyPage, InvalidPage, PageNotAnInteger):
            page = paginator.num_pages
            logs = paginator.page(paginator.num_pages)
        if request.GET.get('check_update', '') == 'true':
            if request.GET.get('last_id') == str(logs[0].id):
                return HttpResponse('noChange')
            else:
                return HttpResponse('Changed')
        context['title'] = _('DNSLog管理')
        context['page'] = page
        context['logs'] = logs
        context['numpages'] = paginator.num_pages
        context['total'] = paginator.count

        query_prefix = ''
        if request.GET.get('ip'):
            query_prefix += 'ip=' + request.GET.get('ip') + '&'
        if request.GET.get('domain'):
            query_prefix += 'domain=' + request.GET.get('domain') + '&'
        context['query_prefix'] = query_prefix
        context['last_id'] = logs[0].id if logs else 0

    elif type == 'web':
        objects = WebLog.objects.filter(user=user)
        if request.GET.get('ip'):
            objects = objects.filter(remote_addr=request.GET.get('ip'))
        if request.GET.get('path'):
            objects = objects.filter(path__icontains=request.GET.get('path'))
        if request.GET.get('headers'):
            objects = objects.filter(headers__icontains=request.GET.get('headers'))
        paginator = Paginator(objects.order_by('-id'), 10)
        try:
            logs = paginator.page(page)
        except(EmptyPage, InvalidPage, PageNotAnInteger):
            page = paginator.num_pages
            logs = paginator.page(paginator.num_pages)
        if request.GET.get('check_update', '') == 'true':
            if request.GET.get('last_id') == str(logs[0].id):
                return HttpResponse('noChange')
            else:
                return HttpResponse('Changed')
        context['title'] = _('WebLog管理')
        context['page'] = page
        context['logs'] = logs
        context['numpages'] = paginator.num_pages
        context['total'] = paginator.count

        query_prefix = ''
        if request.GET.get('ip', ''):
            query_prefix += 'ip=' + request.GET.get('ip') + '&'
        if request.GET.get('path', ''):
            query_prefix += 'path=' + request.GET.get('path') + '&'
        if request.GET.get('headers', ''):
            query_prefix += 'headers=' + request.GET.get('headers') + '&'
        context['query_prefix'] = query_prefix
        context['last_id'] = logs[0].id if logs else 0
    elif type == 'config':
        context['enable_register'] = 'yes'
        context['enable_create_random_user'] = 'yes'
        if user.is_admin:
            for c_name in ['enable_register', 'enable_create_random_user']:
                c = Config.objects.filter(name=c_name)
                if c and 'no' == c[0].value:
                    context[c_name] = 'no'
        context['title'] = _('API配置')
        context['last_id'] = context['total'] = context['page'] = 0
        context['query_prefix'] = ''
        context['host'] = request.scheme + '://' + request.get_host()
    elif type == 'rebind':
        context['title'] = _('DNS重绑定')
        context['last_id'] = 0
        context['total'] = 0
        context['page'] = 0
        context['query_prefix'] = ''
        context['host'] = request.scheme + '://' + request.get_host()
    elif type == 'payloads':
        context['title'] = _('Payloads大全')
    else:
        return HttpResponseRedirect('/')
    context['userdomain'] = user.user_domain + '.' + settings.DNS_DOMAIN
    context['token'] = user.token
    context['username'] = user.username
    context['admin_domain'] = str(settings.ADMIN_DOMAIN)

    return render(request, 'views.html', context)


def api(request, type, username, prefix):
    result = False
    token = request.GET.get('token', '')
    if not User.objects.filter(username=username, token=token):
        return HttpResponse('Invalid token')

    host = "%s.%s.%s" % (prefix, username, settings.DNS_DOMAIN)
    if type == 'dns':
        res = DNSLog.objects.filter(host=host)
        if len(res) > 0:
            result = True
    elif type == 'web':
        res = WebLog.objects.filter(path__contains=host)
        if len(res) > 0:
            result = True
    else:
        return HttpResponseRedirect('/')
    return HttpResponse(result)


def group_api(request, username, prefix):
    token = request.GET.get('token', '')
    if not User.objects.filter(username=username, token=token):
        return HttpResponse('Invalid token')
    postfix = ".%s.%s.%s" % (prefix, username, settings.DNS_DOMAIN)
    res = DNSLog.objects.filter(host__endswith=postfix).order_by('host').values('host').distinct()
    if res:
        res = res[:50]
        data = [item['host'].replace(postfix, '') for item in res]
        text = json.dumps({"success": "true", "data": data})
        return HttpResponse(text, content_type="application/json")
    else:
        return HttpResponse("False")


def as_admin(request):
    userid = request.session.get('userid', None)
    if not userid:
        return redirect('/login')
    user = User.objects.filter(id=userid)[0]
    if user.is_admin:
        su = SysUser.objects.filter(username=user.username, is_superuser=1)
        if su:
            request.user = su[0]
            login(request, su[0])
            return redirect('/admin/')
    return redirect('/')


def config_update(request):
    userid = request.session.get('userid', None)
    config_name = request.GET.get('name', '')
    config_value = request.GET.get('value', '')
    if not userid or config_value not in ('yes', 'no') or \
            config_name not in ['enable_register', 'enable_create_random_user']:
        return HttpResponse('Fail', status=403)
    user = User.objects.filter(id=userid)[0]
    if user.is_admin:
        c = Config.objects.filter(name=config_name)
        if c:
            c[0].value = config_value
            c[0].save()
        else:
            Config.objects.create(name=config_name, value=config_value)
        return HttpResponse('Updated')
    return HttpResponse('Fail', status=403)


def rebind_gen(request):
    userid = request.session.get('userid', None)
    if not userid:
        return HttpResponse('Fail', status=403)

    valid_ip = request.GET.get('valid_ip', '')
    invalid_ip = request.GET.get('invalid_ip', '')
    try:
        valid_ip = hex(struct.unpack("!I", socket.inet_aton(valid_ip))[0])[2:]
        invalid_ip = hex(struct.unpack("!I", socket.inet_aton(invalid_ip))[0])[2:]
        user_domain = request.session.get('username') + '.' + settings.DNS_DOMAIN
        return HttpResponse('%s.%s.r.%s' % (valid_ip, invalid_ip, user_domain))
    except Exception as e:
        return HttpResponse('Fail')
