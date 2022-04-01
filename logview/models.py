from django.db import models
from django.contrib import admin


class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=128, db_index=True)
    email = models.CharField(max_length=128, db_index=True)
    password = models.CharField(max_length=128, db_index=True)
    user_domain = models.CharField(max_length=128, db_index=True)
    token = models.CharField(max_length=32, db_index=True)
    is_admin = models.BooleanField(default=0)
    try_login_counter = models.IntegerField(default=0)
    last_try_login_time = models.DateTimeField(auto_now=True)
    login_ip = models.GenericIPAddressField(db_index=True, default='0.0.0.0')
    is_random_user = models.BooleanField(default=0, db_index=True)

    def __unicode__(self):
        return self.username


class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'password', 'user_domain')


admin.site.register(User, UserAdmin)


class WebLog(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    path = models.CharField(max_length=256, db_index=True)
    remote_addr = models.GenericIPAddressField('remote_addr', db_index=True)
    city = models.CharField(max_length=64, null=True, db_index=True)
    user_agent = models.CharField(max_length=256, null=True, db_index=True)
    created_time = models.DateTimeField(auto_now_add=True)
    headers = models.TextField()

    def __unicode__(self):
        return self.remote_addr

    class Meta:
        ordering = ['-id']


class WebLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'path', 'remote_addr', 'user_agent', 'created_time')


admin.site.register(WebLog, WebLogAdmin)


class DNSLog(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.CharField(max_length=255, db_index=True, null=False)
    type = models.CharField(max_length=8, db_index=True, null=False)
    created_time = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=False, db_index=True)
    city = models.CharField(max_length=255, null=True)

    def __unicode__(self):
        return self.host

    class Meta:
        ordering = ['-id']


class DNSLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'host', 'type', 'created_time')


admin.site.register(DNSLog, DNSLogAdmin)


class Config(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128, db_index=True)
    value = models.CharField(max_length=128, db_index=True)

    def __unicode__(self):
        return self.name


class ConfigAdmin(admin.ModelAdmin):
    list_display = ('name', 'value')


admin.site.register(Config, ConfigAdmin)
