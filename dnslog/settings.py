# coding:utf-8

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '#ma=s-l!2obwj%h-6uu^sbw+4%i2w79%v3^ill62k3&7tjf5dc'

DEBUG = True

ALLOWED_HOSTS = ['*']

# SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'logview',
)

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'dnslog.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'dnslog.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'DB_NAME',
        'USER': 'DB_USER',
        'PASSWORD': 'DB_PASSWORD',
        'HOST': 'DB_HOST',
        'PORT': '3306'
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_L10N = True
USE_TZ = True


STATIC_URL = '/static/'
if DEBUG:
    STATICFILES_DIRS = (os.path.join(BASE_DIR, 'static'),)
else:
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# 用于DNS记录的域名
DNS_DOMAIN = 'eyes.sh'

# 管理后台域名
ADMIN_DOMAIN = ['eyes.sh', 'www.eyes.sh']

# NS域名
NS1_DOMAIN = 'eyes_dns1.lijiejie.com'
NS2_DOMAIN = 'eyes_dns2.lijiejie.com'

# 服务器外网地址
SERVER_IP = '123.123.123.123'

if not DEBUG:
    LOGGING = {}
else:
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
            'verbose': {
                'format': "[%(asctime)s] %(levelname)s [ %(filename)s] [line %(lineno)s] %(message)s",
                'datefmt': "%d/%b/%Y %H:%M:%S"
            },
            'simple': {
                'format': '%(levelname)s %(message)s'
            },
        },
        'handlers': {
            'file': {
                'level': 'DEBUG' if DEBUG else 'INFO',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(LOG_DIR, 'dnslog_debug.log'),
                'formatter': 'verbose',
                'maxBytes': 1024 * 1024 * 1024 * 2,  # 2GB
                'backupCount': 5,
            },
        },
        'loggers': {
            'django': {
                'handlers': ['file'],
                'level': 'DEBUG' if DEBUG else 'INFO',
                'propagate': True,
            },
            'django.utils.autoreload': {
                'level': 'CRITICAL',
            }
        },
    }
