# -*- coding: utf-8 -*-
from django.contrib.sites.models import Site
from django.db.models import Sum
from cerberos.models import FailedAccessAttempt
from cerberos.settings import MAX_FAILED_LOGINS, MEMORY_FOR_FAILED_LOGINS, MAX_FAILSAFE_LOGINS, CERBEROS_BLOCK_LOGLEVEL
from django.shortcuts import render_to_response
from django.template import RequestContext
import datetime

import logging
LOG = logging.getLogger(__name__)

def watch_logins(func):

    def new_func(request, *args, **kwargs):
        if request.POST:
            ip = request.META.get('REMOTE_ADDR', '')
            username = request.POST.get('username')
            failed_access = get_failed_access(ip, username)
            if not check_allowed_login(request, failed_access):
                response = func(request, *args, **kwargs)
                failed_access = process_failed_login(request, response, failed_access)

                if failed_access.locked:
                    response = get_locked_response(request)

            else:
                response = get_locked_response(request)

        else:
            response = func(request, *args, **kwargs)

        return response
    return new_func

def past_limit_for_ip(ip):
    """
    Returns a boolean representing if logins from ip exceed limit.
    """
    past_limit = False
    sum_for_ip = FailedAccessAttempt.objects.filter(ip_address=ip, expired=False).aggregate(Sum('failed_logins'))
    if sum_for_ip.get('failed_logins__sum') >= MAX_FAILED_LOGINS:
        past_limit = True

    return past_limit

def past_limit_for_username(username):
    """
    Returns a boolean representing if logins to username exceed limit.
    """
    past_limit = False
    sum_for_username = FailedAccessAttempt.objects.filter(username=username, expired=False).aggregate(Sum('failed_logins'))
    if sum_for_username.get('failed_logins__sum') >= MAX_FAILED_LOGINS:
        past_limit = True

    return past_limit

def get_failed_access(ip, username):
    """
    Returns the FailedAccessAttempt object for a given IP and username combination.
    """
    try:
        failed_access = FailedAccessAttempt.objects.get(ip_address=ip, username=username, expired=False)
    except FailedAccessAttempt.DoesNotExist:
        failed_access = None

    if failed_access:
        time_remaining = failed_access.get_time_to_forget()
        if time_remaining != None and time_remaining <= 0:
            failed_access.expired = True
            failed_access.save()
            return None

    return failed_access

def check_allowed_login(request, failed_access):
    """
    Checks if the login should be processed or denied.

    It returns the FailedAccessAttempt instance, None, or a faked instance.
    """
    ret_val = None
    ip = request.META.get('REMOTE_ADDR', '')
    username = request.POST.get('username')

    if failed_access:
        if (failed_access.failed_logins >= MAX_FAILSAFE_LOGINS) and (past_limit_for_ip(ip) or past_limit_for_username(username)):
            # Lock the user
            failed_access.locked = True
            failed_access.save()
            getattr(LOG, CERBEROS_BLOCK_LOGLEVEL)('Blocked ip %s for user %s', (ip, username))
            ret_val = True
    elif not MAX_FAILSAFE_LOGINS and (past_limit_for_ip(ip) or past_limit_for_username(username)):
        ret_val = True

    return ret_val

def process_failed_login(request, response, failed_access):
    """
    If is a failed login, save the data in the database.

    It returns the FailedAccessAttempt instance.
    """
    site = Site.objects.get_current()
    ip = request.META.get('REMOTE_ADDR', '')
    user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
    username = request.POST.get('username')
    http_accept = request.META.get('HTTP_ACCEPT', 'unknown'),
    path_info = request.META.get('PATH_INFO', 'unknown')

    if not failed_access:
        failed_access = FailedAccessAttempt(ip_address=ip)

    if request.method == 'POST' and response.status_code != 302:
        # Failed login
        failed_access.site = site
        failed_access.user_agent = user_agent
        failed_access.username = username
        failed_access.failed_logins += 1
        failed_access.get_data = request.GET
        failed_access.post_data = request.POST
        failed_access.http_accept = http_accept
        failed_access.path_info = path_info

        if (failed_access.failed_logins >= MAX_FAILSAFE_LOGINS) and (past_limit_for_ip(ip) or past_limit_for_username(username)):
            # Lock the user
            failed_access.locked = True
            getattr(LOG, CERBEROS_BLOCK_LOGLEVEL)('Blocked ip %s for user %s', (ip, username))
        failed_access.save()
    elif request.method == 'POST' and response.status_code == 302 and failed_access.id and not failed_access.locked:
        # The user logged in successfully. Forgets about the access attempts
        failed_access.expired = True
        failed_access.save()

    return failed_access

def get_locked_response(request):
    ip = request.META.get('REMOTE_ADDR', '')
    return render_to_response('cerberos/user-locked.html',
                              {
                                  'ip':ip,
                                  'login_limit': (MAX_FAILSAFE_LOGINS + MAX_FAILED_LOGINS),
                                  },
                              context_instance=RequestContext(request))
