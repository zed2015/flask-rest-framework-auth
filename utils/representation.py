

def field_repr(field, force_many=False):
    kwargs = field._kwargs
    if force_many:
        kwargs = kwargs.copy()
        kwargs['many'] = True
        kwargs.pop('child', None)

    arg_string = ', '.join([smart_repr(val) for val in field._args])
    kwarg_string = ', '.join([
        '%s=%s' % (key, smart_repr(val))
        for key, val in sorted(kwargs.items())
    ])
    if arg_string and kwarg_string:
        arg_string += ', '

    if force_many:
        class_name = force_many.__class__.__name__
    else:
        class_name = field.__class__.__name__

    return "%s(%s%s)" % (class_name, arg_string, kwarg_string)
