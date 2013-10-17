# Exception hierarchy for chef
# Copyright (c) 2010 Noah Kantrowitz <noah@coderanger.net>

class ChefError(Exception):
    """Top-level Chef error."""


class ChefServerError(ChefError):
    """An error from a Chef server. May include a HTTP response code."""

    def __init__(self, message, code=None):
        self.raw_message = message
        if isinstance(message, list):
            message = u', '.join(m for m in message if m)
        super(ChefError, self).__init__(message)
        self.code = code

    @staticmethod
    def from_error(message, code=None):
        cls = {
            404: ChefServerNotFoundError,
        }.get(code, ChefServerError)
        return cls(message, code)


class ChefServerNotFoundError(ChefServerError):
    """A 404 Not Found server error."""


class ChefAPIVersionError(ChefError):
    """An incompatible API version error"""

class ChefUnsupportedEncryptionVersionError(ChefError):
    def __init__(self, version):
        message = "This version of chef does not support encrypted data bag item format version %s" % version
        return super(ChefError, self).__init__(message)

class ChefDecryptionError(ChefError):
    """Error decrypting data bag value. Most likely the provided key is incorrect"""
