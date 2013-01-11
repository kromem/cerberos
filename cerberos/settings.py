from django.conf import settings

MAX_FAILED_LOGINS = getattr(settings, 'MAX_FAILED_LOGINS', 3)
MAX_FAILSAFE_LOGINS = getattr(settings, 'MAX_FAILSAFE_LOGINS', 0)

# Number of seconds after the failed access attempts are forgotten.
MEMORY_FOR_FAILED_LOGINS = getattr(settings, 'MEMORY_FOR_FAILED_LOGINS', 0)

# Should we reset failed logins for a user on User update?
RESET_FAILED_LOGINS = getattr(settings, 'RESET_FAILED_LOGINS', False)

# What log level should blocks be logged at?
CERBEROS_BLOCK_LOGLEVEL = getattr(settings, 'CERBEROS_BLOCK_LOGLEVEL', 'debug')
