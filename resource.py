"""
Provides an APIView class that is the base of all views in REST framework.
"""
from __future__ import absolute_import
from __future__ import unicode_literals

from flask_restful import Resource
from flask import request, url_for, current_app
from werkzeug.wrappers import Response as ResponseBase
from flask_restful.utils import http_status_message, unpack, OrderedDict
from collections import Mapping
from . import exceptions
from . import status

from flask.globals import _request_ctx_stack, _request_ctx_err_msg
from .request import Request
from flask import Response

def exception_handler(exc, context):
    """
    Returns the response that should be used for any given exception.

    By default we handle the REST framework `APIException`, and also
    Django's built-in `Http404` and `PermissionDenied` exceptions.

    Any unhandled exceptions may return `None`, which will cause a 500 error
    to be raised.
    """
    # if isinstance(exc, Http404):
    #     exc = exceptions.NotFound()
    # elif isinstance(exc, PermissionDenied):
    #     exc = exceptions.PermissionDenied()

    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        # set_rollback()
        # return Response(data, status=exc.status_code, headers=headers)
        return data, exc.status_code, headers

    return None

class AuthResource(Resource):
    """
    Represents an abstract RESTful resource. Concrete resources should
    extend from this class and expose methods for each supported HTTP
    method. If a resource is invoked with an unsupported HTTP method,
    the API will return a response with status 405 Method Not Allowed.
    Otherwise the appropriate method is called and passed all arguments
    from the url rule used when adding the resource to an Api instance. See
    :meth:`~flask_restful.Api.add_resource` for details.
    """
    representations = None
    method_decorators = []
    authentication_classes = []
    permission_classes = []


    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        """
        return [auth() for auth in self.authentication_classes]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        return [permission() for permission in self.permission_classes]

    def initialize_request(self):
        """strong request"""
        new_request = Request(request._get_current_object(), authenticators=self.get_authenticators())
        top = _request_ctx_stack.top
        if top is None:
            raise RuntimeError(_request_ctx_err_msg)
        top.request = new_request
        return new_request


    def initial(self):
        """
        Runs anything that needs to occur prior to calling the method handler.
        """
        # Ensure that the incoming request is permitted
        self.perform_authentication()
        self.check_permissions()

    def perform_authentication(self):
        request.user

    def check_permissions(self):
        """
        Check if the request should be permitted.
        Raises an appropriate exception if the request is not permitted.
        """
        for permission in self.get_permissions():
            if not permission.has_permission(request, self):
                self.permission_denied(
                    message=getattr(permission, 'message', None)
                )

    def permission_denied(self, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.
        """
        if request.authenticators and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        raise exceptions.PermissionDenied(detail=message)

    def middle_func(self):
        self.request = self.initialize_request()
        self.initial()

    def dispatch_request(self, *args, **kwargs):

        # Taken from flask
        #noinspection PyUnresolvedReferences
        self.args = args
        self.kwargs = kwargs
        meth = getattr(self, request.method.lower(), None)
        if meth is None and request.method == 'HEAD':
            meth = getattr(self, 'get', None)
        assert meth is not None, 'Unimplemented method %r' % request.method
        try:
            self.middle_func()
        except Exception as exc:
            resp = self.handle_exception(exc)
            return resp
        else:

            if isinstance(self.method_decorators, Mapping):
                decorators = self.method_decorators.get(request.method.lower(), [])
            else:
                decorators = self.method_decorators

            for decorator in decorators:
                meth = decorator(meth)

            resp = meth(*args, **kwargs)

        if isinstance(resp, ResponseBase):  # There may be a better way to test
            return resp

        representations = self.representations or OrderedDict()
        #noinspection PyUnresolvedReferences
        mediatype = request.accept_mimetypes.best_match(representations, default=None)
        if mediatype in representations:
            data, code, headers = unpack(resp)
            resp = representations[mediatype](data, code, headers)
            resp.headers['Content-Type'] = mediatype
            return resp

        return resp

    def handle_exception(self, exc):
        """
        Handle any exception that occurs, by returning an appropriate response,
        or re-raising the error.
        """
        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate header for 401 responses, else coerce to 403
            auth_header = self.get_authenticate_header(self.request)

            if auth_header:
                exc.auth_header = auth_header
            else:
                exc.status_code = status.HTTP_403_FORBIDDEN

        exception_handler = self.get_exception_handler()

        context = self.get_exception_handler_context()
        response = exception_handler(exc, context)

        if response is None:
            self.raise_uncaught_exception(exc)

        # response.exception = True
        return response

    def get_exception_handler(self):
        """
        Returns the exception handler that this view uses.
        """
        return exception_handler


    def get_exception_handler_context(self):
        """
        Returns a dict that is passed through to EXCEPTION_HANDLER,
        as the `context` argument.
        """
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_authenticate_header(self, request):
        """
        If a request is unauthenticated, determine the WWW-Authenticate
        header to use for 401 responses, if any.
        """
        authenticators = self.get_authenticators()
        if authenticators:
            return authenticators[0].authenticate_header(request)

    def raise_uncaught_exception(self, exc):
        # if settings.DEBUG:
        #     request = self.request
        #     renderer_format = getattr(request.accepted_renderer, 'format')
        #     use_plaintext_traceback = renderer_format not in ('html', 'api', 'admin')
        #     request.force_plaintext_errors(use_plaintext_traceback)
        raise exc

# class APIView(object):
#
#     # The following policies may be set at either globally, or per-view.
#     renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
#     parser_classes = api_settings.DEFAULT_PARSER_CLASSES
#     authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
#     throttle_classes = api_settings.DEFAULT_THROTTLE_CLASSES
#     permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
#     content_negotiation_class = api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS
#     metadata_class = api_settings.DEFAULT_METADATA_CLASS
#     versioning_class = api_settings.DEFAULT_VERSIONING_CLASS
#
#     # Allow dependency injection of other settings to make testing easier.
#     settings = api_settings
#
#     schema = DefaultSchema()
#
#     @classmethod
#     def as_view(cls, **initkwargs):
#         """
#         Store the original class on the view function.
#
#         This allows us to discover information about the view when we do URL
#         reverse lookups.  Used for breadcrumb generation.
#         """
#         if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
#             def force_evaluation():
#                 raise RuntimeError(
#                     'Do not evaluate the `.queryset` attribute directly, '
#                     'as the result will be cached and reused between requests. '
#                     'Use `.all()` or call `.get_queryset()` instead.'
#                 )
#             cls.queryset._fetch_all = force_evaluation
#
#         view = super(APIView, cls).as_view(**initkwargs)
#         view.cls = cls
#         view.initkwargs = initkwargs
#
#         # Note: session based authentication is explicitly CSRF validated,
#         # all other authentication is CSRF exempt.
#         return csrf_exempt(view)
#
#     @property
#     def allowed_methods(self):
#         """
#         Wrap Django's private `_allowed_methods` interface in a public property.
#         """
#         return self._allowed_methods()
#
#     @property
#     def default_response_headers(self):
#         headers = {
#             'Allow': ', '.join(self.allowed_methods),
#         }
#         if len(self.renderer_classes) > 1:
#             headers['Vary'] = 'Accept'
#         return headers
#
#     def http_method_not_allowed(self, request, *args, **kwargs):
#         """
#         If `request.method` does not correspond to a handler method,
#         determine what kind of exception to raise.
#         """
#         raise exceptions.MethodNotAllowed(request.method)
#
#     def permission_denied(self, request, message=None):
#         """
#         If request is not permitted, determine what kind of exception to raise.
#         """
#         if request.authenticators and not request.successful_authenticator:
#             raise exceptions.NotAuthenticated()
#         raise exceptions.PermissionDenied(detail=message)
#
#     def throttled(self, request, wait):
#         """
#         If request is throttled, determine what kind of exception to raise.
#         """
#         raise exceptions.Throttled(wait)
#
#     def get_authenticate_header(self, request):
#         """
#         If a request is unauthenticated, determine the WWW-Authenticate
#         header to use for 401 responses, if any.
#         """
#         authenticators = self.get_authenticators()
#         if authenticators:
#             return authenticators[0].authenticate_header(request)
#
#     def get_parser_context(self, http_request):
#         """
#         Returns a dict that is passed through to Parser.parse(),
#         as the `parser_context` keyword argument.
#         """
#         # Note: Additionally `request` and `encoding` will also be added
#         #       to the context by the Request object.
#         return {
#             'view': self,
#             'args': getattr(self, 'args', ()),
#             'kwargs': getattr(self, 'kwargs', {})
#         }
#
#     def get_renderer_context(self):
#         """
#         Returns a dict that is passed through to Renderer.render(),
#         as the `renderer_context` keyword argument.
#         """
#         # Note: Additionally 'response' will also be added to the context,
#         #       by the Response object.
#         return {
#             'view': self,
#             'args': getattr(self, 'args', ()),
#             'kwargs': getattr(self, 'kwargs', {}),
#             'request': getattr(self, 'request', None)
#         }
#
#     def get_exception_handler_context(self):
#         """
#         Returns a dict that is passed through to EXCEPTION_HANDLER,
#         as the `context` argument.
#         """
#         return {
#             'view': self,
#             'args': getattr(self, 'args', ()),
#             'kwargs': getattr(self, 'kwargs', {}),
#             'request': getattr(self, 'request', None)
#         }
#
#     def get_view_name(self):
#         """
#         Return the view name, as used in OPTIONS responses and in the
#         browsable API.
#         """
#         func = self.settings.VIEW_NAME_FUNCTION
#         return func(self)
#
#     def get_view_description(self, html=False):
#         """
#         Return some descriptive text for the view, as used in OPTIONS responses
#         and in the browsable API.
#         """
#         func = self.settings.VIEW_DESCRIPTION_FUNCTION
#         return func(self, html)
#
#     # API policy instantiation methods
#
#     def get_format_suffix(self, **kwargs):
#         """
#         Determine if the request includes a '.json' style format suffix
#         """
#         if self.settings.FORMAT_SUFFIX_KWARG:
#             return kwargs.get(self.settings.FORMAT_SUFFIX_KWARG)
#
#     def get_renderers(self):
#         """
#         Instantiates and returns the list of renderers that this view can use.
#         """
#         return [renderer() for renderer in self.renderer_classes]
#
#     def get_parsers(self):
#         """
#         Instantiates and returns the list of parsers that this view can use.
#         """
#         return [parser() for parser in self.parser_classes]
#
#     def get_authenticators(self):
#         """
#         Instantiates and returns the list of authenticators that this view can use.
#         """
#         return [auth() for auth in self.authentication_classes]
#
#     def get_permissions(self):
#         """
#         Instantiates and returns the list of permissions that this view requires.
#         """
#         return [permission() for permission in self.permission_classes]
#
#     def get_throttles(self):
#         """
#         Instantiates and returns the list of throttles that this view uses.
#         """
#         return [throttle() for throttle in self.throttle_classes]
#
#     def get_content_negotiator(self):
#         """
#         Instantiate and return the content negotiation class to use.
#         """
#         if not getattr(self, '_negotiator', None):
#             self._negotiator = self.content_negotiation_class()
#         return self._negotiator
#
#     def get_exception_handler(self):
#         """
#         Returns the exception handler that this view uses.
#         """
#         return self.settings.EXCEPTION_HANDLER
#
#     # API policy implementation methods
#
#     def perform_content_negotiation(self, request, force=False):
#         """
#         Determine which renderer and media type to use render the response.
#         """
#         renderers = self.get_renderers()
#         conneg = self.get_content_negotiator()
#
#         try:
#             return conneg.select_renderer(request, renderers, self.format_kwarg)
#         except Exception:
#             if force:
#                 return (renderers[0], renderers[0].media_type)
#             raise
#
#     def perform_authentication(self, request):
#         """
#         Perform authentication on the incoming request.
#
#         Note that if you override this and simply 'pass', then authentication
#         will instead be performed lazily, the first time either
#         `request.user` or `request.auth` is accessed.
#         """
#         request.user
#
#     def check_permissions(self, request):
#         """
#         Check if the request should be permitted.
#         Raises an appropriate exception if the request is not permitted.
#         """
#         for permission in self.get_permissions():
#             if not permission.has_permission(request, self):
#                 self.permission_denied(
#                     request, message=getattr(permission, 'message', None)
#                 )
#
#     def check_object_permissions(self, request, obj):
#         """
#         Check if the request should be permitted for a given object.
#         Raises an appropriate exception if the request is not permitted.
#         """
#         for permission in self.get_permissions():
#             if not permission.has_object_permission(request, self, obj):
#                 self.permission_denied(
#                     request, message=getattr(permission, 'message', None)
#                 )
#
#     def check_throttles(self, request):
#         """
#         Check if request should be throttled.
#         Raises an appropriate exception if the request is throttled.
#         """
#         for throttle in self.get_throttles():
#             if not throttle.allow_request(request, self):
#                 self.throttled(request, throttle.wait())
#
#     def determine_version(self, request, *args, **kwargs):
#         """
#         If versioning is being used, then determine any API version for the
#         incoming request. Returns a two-tuple of (version, versioning_scheme)
#         """
#         if self.versioning_class is None:
#             return (None, None)
#         scheme = self.versioning_class()
#         return (scheme.determine_version(request, *args, **kwargs), scheme)
#
#     # Dispatch methods
#
#     def initialize_request(self, request, *args, **kwargs):
#         """
#         Returns the initial request object.
#         """
#         parser_context = self.get_parser_context(request)
#
#         return Request(
#             request,
#             parsers=self.get_parsers(),
#             authenticators=self.get_authenticators(),
#             negotiator=self.get_content_negotiator(),
#             parser_context=parser_context
#         )
#
#     def initial(self, request, *args, **kwargs):
#         """
#         Runs anything that needs to occur prior to calling the method handler.
#         """
#         self.format_kwarg = self.get_format_suffix(**kwargs)
#
#         # Perform content negotiation and store the accepted info on the request
#         neg = self.perform_content_negotiation(request)
#         request.accepted_renderer, request.accepted_media_type = neg
#
#         # Determine the API version, if versioning is in use.
#         version, scheme = self.determine_version(request, *args, **kwargs)
#         request.version, request.versioning_scheme = version, scheme
#
#         # Ensure that the incoming request is permitted
#         self.perform_authentication(request)
#         self.check_permissions(request)
#         self.check_throttles(request)
#
#     def finalize_response(self, request, response, *args, **kwargs):
#         """
#         Returns the final response object.
#         """
#         # Make the error obvious if a proper response is not returned
#         assert isinstance(response, HttpResponseBase), (
#                 'Expected a `Response`, `HttpResponse` or `HttpStreamingResponse` '
#                 'to be returned from the view, but received a `%s`'
#                 % type(response)
#         )
#
#         if isinstance(response, Response):
#             if not getattr(request, 'accepted_renderer', None):
#                 neg = self.perform_content_negotiation(request, force=True)
#                 request.accepted_renderer, request.accepted_media_type = neg
#
#             response.accepted_renderer = request.accepted_renderer
#             response.accepted_media_type = request.accepted_media_type
#             response.renderer_context = self.get_renderer_context()
#
#         # Add new vary headers to the response instead of overwriting.
#         vary_headers = self.headers.pop('Vary', None)
#         if vary_headers is not None:
#             patch_vary_headers(response, cc_delim_re.split(vary_headers))
#
#         for key, value in self.headers.items():
#             response[key] = value
#
#         return response
#
#     def handle_exception(self, exc):
#         """
#         Handle any exception that occurs, by returning an appropriate response,
#         or re-raising the error.
#         """
#         if isinstance(exc, (exceptions.NotAuthenticated,
#                             exceptions.AuthenticationFailed)):
#             # WWW-Authenticate header for 401 responses, else coerce to 403
#             auth_header = self.get_authenticate_header(self.request)
#
#             if auth_header:
#                 exc.auth_header = auth_header
#             else:
#                 exc.status_code = status.HTTP_403_FORBIDDEN
#
#         exception_handler = self.get_exception_handler()
#
#         context = self.get_exception_handler_context()
#         response = exception_handler(exc, context)
#
#         if response is None:
#             self.raise_uncaught_exception(exc)
#
#         response.exception = True
#         return response
#
#     def raise_uncaught_exception(self, exc):
#         if settings.DEBUG:
#             request = self.request
#             renderer_format = getattr(request.accepted_renderer, 'format')
#             use_plaintext_traceback = renderer_format not in ('html', 'api', 'admin')
#             request.force_plaintext_errors(use_plaintext_traceback)
#         raise
#
#     # Note: Views are made CSRF exempt from within `as_view` as to prevent
#     # accidental removal of this exemption in cases where `dispatch` needs to
#     # be overridden.
#     def dispatch(self, request, *args, **kwargs):
#         """
#         `.dispatch()` is pretty much the same as Django's regular dispatch,
#         but with extra hooks for startup, finalize, and exception handling.
#         """
#         self.args = args
#         self.kwargs = kwargs
#         request = self.initialize_request(request, *args, **kwargs)
#         self.request = request
#         self.headers = self.default_response_headers  # deprecate?
#
#         try:
#             self.initial(request, *args, **kwargs)
#
#             # Get the appropriate handler method
#             if request.method.lower() in self.http_method_names:
#                 handler = getattr(self, request.method.lower(),
#                                   self.http_method_not_allowed)
#             else:
#                 handler = self.http_method_not_allowed
#
#             response = handler(request, *args, **kwargs)
#
#         except Exception as exc:
#             response = self.handle_exception(exc)
#
#         self.response = self.finalize_response(request, response, *args, **kwargs)
#         return self.response
#
#     def options(self, request, *args, **kwargs):
#         """
#         Handler method for HTTP 'OPTIONS' request.
#         """
#         if self.metadata_class is None:
#             return self.http_method_not_allowed(request, *args, **kwargs)
#         data = self.metadata_class().determine_metadata(request, self)
#         return Response(data, status=status.HTTP_200_OK)
