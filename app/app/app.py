#!/usr/bin/env python3

import signal
import socket
import sys

import server
from config import config
from log import logger, sanic_logger
import pyroscope
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import (Resource, SERVICE_NAME,
                                         DEPLOYMENT_ENVIRONMENT)

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
    init_o11y()
    server.init(app, config.http_request_timeout, config.http_response_timeout)


@server.server.before_server_stop
async def before_server_stop(app, loop):
    pass


def init_o11y():
    if not config.o11y_enabled:
        return
    if config.tracing_server != "":
        resource_attributes = {
            SERVICE_NAME: config.application_name,
            DEPLOYMENT_ENVIRONMENT: "production"
        }
        if type(config.tags) == dict:
            for k, v in config.tags.items():
                resource_attributes[k] = v
        trace_provider = TracerProvider(
            resource=Resource.create(resource_attributes))
        otlpSpanExporter = OTLPSpanExporter(endpoint=config.tracing_server)
        trace_provider.add_span_processor(BatchSpanProcessor(otlpSpanExporter))
        trace.set_tracer_provider(trace_provider)
    if config.profiler_server != "":
        pyroscope.configure(app_name=config.application_name,
                            server_address=config.profiler_server,
                            log_level="debug",
                            sample_rate=100,
                            detect_subprocesses=True,
                            tags=config.tags)


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
