import logging
from logging import FileHandler, StreamHandler
from logging.handlers import SysLogHandler

LOG_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARN,
    "error": logging.ERROR,
}


class LoggerManager(object):

    LOGGER = logging.getLogger('root')

    def __init__(self, model_name, log_level, log_file=None, log_stream=None):
        self.model_name = model_name
        self.log_level = LOG_LEVEL_MAP[log_level]
        self.log_file = log_file
        self.log_stream = log_stream

    @property
    def syslog_handler(self):
        syslog_handler = SysLogHandler(address='/dev/log',
                                       facility=SysLogHandler.LOG_LOCAL2)
        syslog_handler.setFormatter(
            logging.Formatter(self.model_name + '/%(module)s: %(message)s'))
        return syslog_handler

    @property
    def file_handler(self):
        file_handler = FileHandler(self.log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s T%(thread)d-%(threadName)s '
                              '%(levelname)s %(module)s.'
                              '%(funcName)s.%(lineno)s: %(message)s'))
        return file_handler

    @property
    def stream_handler(self):
        stream_handler = StreamHandler(stream=self.log_stream)
        stream_handler.setFormatter(
            logging.Formatter('%(asctime)s T%(thread)d-%(threadName)s '
                              '%(levelname)s %(module)s.'
                              '%(funcName)s.%(lineno)s: %(message)s'))
        return stream_handler

    @classmethod
    def get_logger(cls, name='root'):
        return cls.LOGGER

    def init_logger(self):
        self.LOGGER.setLevel(self.log_level)
        self.LOGGER.addHandler(self.stream_handler)
        #self.LOGGER.addHandler(self.file_handler)
        #self.LOGGER.addHandler(self.syslog_handler)


def getLogger(name='root'):
    return LoggerManager.get_logger(name)
