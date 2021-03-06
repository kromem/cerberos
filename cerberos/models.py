# -*- coding: utf-8 -*-
from django.contrib.sites.models import Site
from django.contrib.auth.models import User
from django.db import models
from django.dispatch import receiver
from django.db.models.signals import pre_save
#from django.template.defaultfilters import slugify
from django.utils.translation import ugettext_lazy as _ 
#from django.core.urlresolvers import reverse
#from django.contrib.auth.models import User
from cerberos.settings import MEMORY_FOR_FAILED_LOGINS, RESET_FAILED_LOGINS
import datetime

try:
    from django.utils import timezone
except ImportError:
    from datetime import datetime as timezone

class FailedAccessAttempt(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    site = models.ForeignKey(Site, verbose_name=_(u'Site'))
    ip_address = models.IPAddressField(verbose_name=_(u'IP Address'), null=True, db_index=True)
    user_agent = models.CharField(max_length=255, verbose_name=_(u'User Agent'), blank=False,
            help_text=_(u'User agent used in the login attempt'))
    username = models.CharField(max_length=255, verbose_name=_(u'Username'), blank=False, db_index=True,
            help_text=_(u'Username used to login'))
    failed_logins = models.PositiveIntegerField(verbose_name=_(u'Failed logins'), default=0,
            help_text=_(u'Failed logins for this IP and Username'))
    locked = models.BooleanField(verbose_name=_(u'Locked'), default=False, db_index=True,
            help_text=_(u'Indicates if the IP has been locked out.'))
    expired = models.BooleanField(verbose_name=_(u'Expired'), default=False, 
            help_text=_(u'Indicates if the timeout has expired.'))

    get_data = models.TextField('GET Data')
    post_data = models.TextField('POST Data')
    http_accept = models.TextField('HTTP Accept')
    path_info = models.CharField('Path', max_length=255)

    class Meta:
        verbose_name = _(u'Failed access attempt')
        verbose_name_plural = _(u'Failed access attempts')
        
    def __unicode__(self):
        return u'%s: %s' % (self.username, self.ip_address )

    def get_time_to_forget(self):
        """
        Returns the time until this access attempt is forgotten.
        """
        if MEMORY_FOR_FAILED_LOGINS > 0:
            now = timezone.now()
            delta = now - self.modified
            time_remaining = MEMORY_FOR_FAILED_LOGINS - delta.seconds
            return time_remaining
        else:
            return None

    def get_time_to_forget_text(self):
        """
        Returns the text for the admin based on the time to forget
        """
        time_remaining = self.get_time_to_forget()

        if not self.locked:
            return _(u'Not locked yet')
        elif time_remaining == None:
            return _(u'Infinite')
        elif time_remaining <= 0:
            return _(u'Forgotten')
        else:
            return _(u'%(time_remaining)s seconds' % {'time_remaining': time_remaining})
    get_time_to_forget.short_description = _(u'Time to forget')

@receiver(pre_save, sender=User, dispatch_uid="expire_failedaccess")
def expire_for_user(sender, **kwargs):
    """Expires all FailedAccessAttempt objects for a user.

    When a User's password is updated, expires all FailedAccessAttempts for them.
    """
    if RESET_FAILED_LOGINS and not (kwargs.get('created', False) and not kwargs.get('raw', False)):
        user = kwargs['instance']
        try:
            current_user = User.objects.get(id=user.id)
        except User.DoesNotExist:    
            current_user = None
        else:
            if current_user.password != user.password:
                FailedAccessAttempt.objects.filter(username=user.username).update(expired=True)
    return
