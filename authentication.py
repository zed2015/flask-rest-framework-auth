"""
Provides various authentication policies.
"""
from __future__ import unicode_literals
from . import exceptions
from flask import g, current_app
from flask_login import current_user
from .settings import api_settings
from itsdangerous import TimedJSONWebSignatureSerializer as JWT
from itsdangerous import SignatureExpired, BadSignature


def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    header = request._request.headers.get('Authorization', b'')
    return header


def get_user_model():
    from app.models.user import User
    return User


class BaseAuthentication(object):
    """
    All authentication classes should extend BaseAuthentication.
    """

    def authenticate(self, request):
        """
        Authenticate the request and return a two-tuple of (user, token).
        """
        raise NotImplementedError(".authenticate() must be overridden.")

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        pass


class SessionAuthentication(BaseAuthentication):
    """
    session authentication
    """

    def authenticate(self, request):
        """
        Returns a `User` if the request session currently has a logged in user.
        Otherwise returns `None`.
        """

        # Get the session-based user from the underlying HttpRequest object
        user = current_user
        # Unauthenticated, CSRF validation not required
        if not user or not user.is_active:
            return None

        # self.enforce_csrf(request)
        # CSRF passed with authenticated user
        return (user, None)

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session based authentication.
        """
        # ToDo
        pass


class BaseJSONWebTokenAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.
    """
    def get_jwt_value(self, request):
        pass

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        s = JWT(current_app.config['SECRET_KEY'])
        try:
            payload = s.loads(jwt_value)
        except SignatureExpired:
            msg = 'Signature has expired.'
            raise exceptions.AuthenticationFailed(msg)
        except BadSignature:
            msg = 'Error decoding signature.'
            raise exceptions.AuthenticationFailed(msg)

        user = self.authenticate_credentials(payload)
        return (user, payload)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        User = get_user_model()
        user_id = payload.get('id')

        if not user_id:
            msg = 'Invalid payload.'
            raise exceptions.AuthenticationFailed(msg)
        user = User.query.get(user_id)
        if not user:
            msg = 'Invalid signature.'
            raise exceptions.AuthenticationFailed(msg)
        if not user.is_active:
            msg = 'User account is disabled.'
            raise exceptions.AuthenticationFailed(msg)
        return user


class JSONWebTokenAuthentication(BaseJSONWebTokenAuthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:
        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split(None, 1)

        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX

        if not auth:
            # if api_settings.JWT_AUTH_COOKIE:
            #     return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if auth[0].lower() != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = 'Invalid Authorization header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid Authorization header. Credentials string ' \
                  'should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)
        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm)

# class TokenAuthentication(BaseAuthentication):
#     """
#     Simple token based authentication.
#
#     Clients should authenticate by passing the token key in the "Authorization"
#     HTTP header, prepended with the string "Token ".  For example:
#
#         Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
#     """
#
#     keyword = 'Token'
#     model = None
#
#     def get_model(self):
#         if self.model is not None:
#             return self.model
#         from rest_framework.authtoken.models import Token
#         return Token
#
#     """
#     A custom token model may be used, but must have the following properties.
#
#     * key -- The string identifying the token
#     * user -- The user to which the token belongs
#     """
#
#     def authenticate(self, request):
#         auth = get_authorization_header(request).split()
#
#         if not auth or auth[0].lower() != self.keyword.lower().encode():
#             return None
#
#         if len(auth) == 1:
#             msg = _('Invalid token header. No credentials provided.')
#             raise exceptions.AuthenticationFailed(msg)
#         elif len(auth) > 2:
#             msg = _('Invalid token header. Token string should not contain spaces.')
#             raise exceptions.AuthenticationFailed(msg)
#
#         try:
#             token = auth[1].decode()
#         except UnicodeError:
#             msg = _('Invalid token header. Token string should not contain invalid characters.')
#             raise exceptions.AuthenticationFailed(msg)
#
#         return self.authenticate_credentials(token)
#
#     def authenticate_credentials(self, key):
#         model = self.get_model()
#         try:
#             token = model.objects.select_related('user').get(key=key)
#         except model.DoesNotExist:
#             raise exceptions.AuthenticationFailed(_('Invalid token.'))
#
#         if not token.user.is_active:
#             raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))
#
#         return (token.user, token)
#
#     def authenticate_header(self, request):
#         return self.keyword



