import sys
import logging

from smurf import app
import smurf.views


reload(sys)
sys.setdefaultencoding('utf-8')

#app.config.from_object("config")


if __name__ == '__main__':
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('0.0.0.0', 8913), app, handler_class=WebSocketHandler)
    server.serve_forever()
