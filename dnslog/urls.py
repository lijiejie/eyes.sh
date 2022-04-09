# coding=utf-8

from django.urls import path, re_path, include
from django.contrib import admin
from logview import views

urlpatterns = [
    re_path(r'^admin/login', views.index),
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^login', views.do_login, name='login'),
    re_path(r'^random_id_login', views.random_id_login, name='random_id_login'),
    re_path(r'^register', views.register, name='register'),
    re_path(r'^logout/', views.do_logout, name='logout'),
    re_path(r'^api/group/dns/(.+?)/(.+?)/$', views.group_api, name='group_api'),
    re_path(r'^api/(.+?)/(.+?)/(.+?)/$', views.api, name='api'),
    re_path(r'^dns/$', views.dns_view, name='dns_view'),
    re_path(r'^dns/delete$', views.dns_delete, name='dns_delete'),
    re_path(r'^web/$', views.web_view, name='web_view'),
    re_path(r'^web/delete$', views.web_delete, name='web_delete'),
    re_path(r'^config/$', views.config_view, name='config_view'),
    re_path(r'^payloads/$', views.payloads_view, name='payloads_view'),
    re_path(r'^rebind/$', views.rebind_view, name='rebind_view'),
    re_path(r'^rebind/gen$', views.rebind_gen, name='rebind_gen'),
    re_path(r'^as_admin/$', views.as_admin, name='as_admin'),
    re_path(r'^config/update$', views.config_update, name='config_update'),
    path('i18n/', include('django.conf.urls.i18n')),
    re_path(r'^.*$', views.index, name='index'),
]
