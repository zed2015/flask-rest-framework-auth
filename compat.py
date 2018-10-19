"""
The `compat` module provides support for backwards compatibility with older
versions of Django/Python, and compatibility wrappers around optional packages.
"""

from __future__ import unicode_literals

from flask_settings import settings
from .core import validators
import six
# from django.views.generic import View

# try:
#     from django.urls import (  # noqa
#         URLPattern,
#         URLResolver,
#     )
# except ImportError:
#     # Will be removed in Django 2.0
#     from django.urls import (  # noqa
#         RegexURLPattern as URLPattern,
#         RegexURLResolver as URLResolver,
#     )


def get_original_route(urlpattern):
    """
    Get the original route/regex that was typed in by the user into the path(), re_path() or url() directive. This
    is in contrast with get_regex_pattern below, which for RoutePattern returns the raw regex generated from the path().
    """
    if hasattr(urlpattern, 'pattern'):
        # Django 2.0
        return str(urlpattern.pattern)
    else:
        # Django < 2.0
        return urlpattern.regex.pattern


def get_regex_pattern(urlpattern):
    """
    Get the raw regex out of the urlpattern's RegexPattern or RoutePattern. This is always a regular expression,
    unlike get_original_route above.
    """
    if hasattr(urlpattern, 'pattern'):
        # Django 2.0
        return urlpattern.pattern.regex.pattern
    else:
        # Django < 2.0
        return urlpattern.regex.pattern


def is_route_pattern(urlpattern):
    if hasattr(urlpattern, 'pattern'):
        # Django 2.0
        from django.urls.resolvers import RoutePattern
        return isinstance(urlpattern.pattern, RoutePattern)
    else:
        # Django < 2.0
        return False



def unicode_repr(instance):
    # Get the repr of an instance, but ensure it is a unicode string
    # on both python 3 (already the case) and 2 (not the case).
    if six.PY2:
        return repr(instance).decode('utf-8')
    return repr(instance)


def unicode_to_repr(value):
    # Coerce a unicode string to the correct repr return type, depending on
    # the Python version. We wrap all our `__repr__` implementations with
    # this and then use unicode throughout internally.
    if six.PY2:
        return value.encode('utf-8')
    return value


def unicode_http_header(value):
    # Coerce HTTP header value to unicode.
    if isinstance(value, six.binary_type):
        return value.decode('iso-8859-1')
    return value


def distinct(queryset, base):
    if settings.DATABASES[queryset.db]["ENGINE"] == "django.db.backends.oracle":
        # distinct analogue for Oracle users
        return base.filter(pk__in=set(queryset.values_list('pk', flat=True)))
    return queryset.distinct()



# `separators` argument to `json.dumps()` differs between 2.x and 3.x
# See: https://bugs.python.org/issue22767
if six.PY3:
    SHORT_SEPARATORS = (',', ':')
    LONG_SEPARATORS = (', ', ': ')
    INDENT_SEPARATORS = (',', ': ')
else:
    SHORT_SEPARATORS = (b',', b':')
    LONG_SEPARATORS = (b', ', b': ')
    INDENT_SEPARATORS = (b',', b': ')


class CustomValidatorMessage(object):
    """
    We need to avoid evaluation of `lazy` translated `message` in `django.core.validators.BaseValidator.__init__`.
    https://github.com/django/django/blob/75ed5900321d170debef4ac452b8b3cf8a1c2384/django/core/validators.py#L297

    Ref: https://github.com/encode/django-rest-framework/pull/5452
    """

    def __init__(self, *args, **kwargs):
        self.message = kwargs.pop('message', self.message)
        super(CustomValidatorMessage, self).__init__(*args, **kwargs)


class MinValueValidator(CustomValidatorMessage, validators.MinValueValidator):
    pass


class MaxValueValidator(CustomValidatorMessage, validators.MaxValueValidator):
    pass


class MinLengthValidator(CustomValidatorMessage, validators.MinLengthValidator):
    pass


class MaxLengthValidator(CustomValidatorMessage, validators.MaxLengthValidator):
    pass


