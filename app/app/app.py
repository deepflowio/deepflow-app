#!/usr/bin/env python3

import signal
import socket
import sys

import server
from config import config
from log import logger, sanic_logger

log = logger.getLogger(__name__)


def signal_handler(sig, frame):
    if sig == signal.SIGTERM:
        log.info('Terminating Cleaner ...')
        sys.exit(0)
    elif sig == signal.SIGHUP:
        log.info('Reloading config.yaml ...')
        config.is_valid()
        log.info('config.yaml reloaded.')


@server.server.before_server_start
async def notify_server_started(app, loop):
    server.init(app, config.http_request_timeout, config.http_response_timeout)


@server.server.before_server_stop
async def before_server_stop(app, loop):
    pass


def main():
    logger_manager = logger.LoggerManager('deepflow-app',
                                          config.log_level,
                                          log_stream=sys.stdout)
    logger_manager.init_logger()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    log.info('Launching Deepflow-app ...')
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', config.listen_port))
    server.server.run(workers=config.worker_numbers,
                      sock=sock,
                      protocol=sanic_logger.DFHttpProtocol)


if __name__ == '__main__':
    main()
