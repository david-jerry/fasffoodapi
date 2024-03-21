# Put this code in a module, for example, utils/request_context.py

from contextlib import contextmanager
from contextvars import ContextVar

# Create a ContextVar named "request" with a default value of None
_request_var = ContextVar("request", default=None)


# Override __getattr__ to customize attribute access
def __getattr__(name):
    if name == "request":
        return _request_var.get()
    raise AttributeError(name)


@contextmanager
def request_context(request):
    """
    Context manager to set and access the current request within a specific context.

    Usage:
    with request_context(request):
        # Your code here
        # The "request" variable is accessible within this context

    Example Usage in a Django View or Utility Function:
    from utils.request_context import request_context

    def your_view(request):
        with request_context(request):
            # Your code here
            # The "request" variable is accessible within this context
            print(request.user)
            # ...

    Note: Import the request_context function and use it with a "with" statement.
    Note: Ensure that the request object is passed to the request_context function.
    """
    # Set the value of the "request" ContextVar to the provided request
    token = _request_var.set(request)
    try:
        yield
    finally:
        # Reset the "request" ContextVar to its original value
        _request_var.reset(token)


