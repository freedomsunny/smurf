import logging
from flask import g


class ContextFilter(logging.Filter):
    """
    This is a filter which injects contextual information into the log.
    """

    def filter(self, record):
        if g and hasattr(g, 'user') and g.user:
            record.user = g.user.name
        else:
            record.user = ''
        return True
