import yaml
import sys

CONFIG_FILE = "/etc/deepflow/app.yaml"


class Config(object):

    def __init__(self):
        pass

    def parse_log(self, cfg):
        self.log_level = cfg.get('log-level', 'info')
        self.log_file = cfg.get('log-file', '/etc/deepflow/app.log')
        self.worker_numbers = cfg.get('worker_numbers', 10)

    def parse_spec(self, cfg):
        spec = cfg.get('spec')
        self.l7_tracing_limit = spec.get('l7_tracing_limit', 100)
        self.max_iteration = spec.get('max_iteration', 30)
        self.network_delay_us = spec.get('network_delay_us', 1000000)
        self.allow_multiple_trace_ids_in_tracing_result = spec.get(
            'allow_multiple_trace_ids_in_tracing_result', False)
        self.call_apm_api_to_supplement_trace = spec.get(
            'call_apm_api_to_supplement_trace', False)

    def parse_querier(self, cfg):
        querier = cfg.get('querier', dict())
        self.querier_server = querier.get('host', 'deepflow-server')
        self.querier_port = querier.get('port', 20416)
        self.querier_timeout = querier.get('timeout', 60)

    def parse_controller(self, cfg):
        controller = cfg.get('controller', dict())
        self.controller_server = controller.get('host', 'deepflow-server')
        self.controller_port = controller.get('port', 20417)
        self.controller_timeout = controller.get('timeout', 60)

    def parse_o11y(self, cfg):
        o11y = cfg.get('o11y', dict())
        self.o11y_enabled = o11y.get('enabled', False)
        self.application_name = o11y.get('application_name', 'deepflow-app')
        self.profiler_server = o11y.get(
            'profiler_server', 'http://deepflow-agent/api/v1/profile')
        self.tracing_server = o11y.get('tracing_server',
                                       'http://deepflow-agent/api/v1/trace')
        self.tags = o11y.get('tags', {})

    def parse(self, config_path):
        with open(config_path, 'r') as config_file:
            cfg = yaml.safe_load(config_file).get("app", {})
            self.listen_port = cfg.get('listen-port')
            self.http_request_timeout = cfg.get('http_request_timeout', 600)
            self.http_response_timeout = cfg.get('http_response_timeout', 600)
            self.parse_log(cfg)
            self.parse_spec(cfg)
            self.parse_querier(cfg)
            self.parse_controller(cfg)
            self.parse_o11y(cfg)

    def is_valid(self, config_path):
        try:
            self.parse(config_path)
        except Exception as e:
            print("Yaml Error: %s" % e)
            sys.exit(1)


config = Config()
config.is_valid(CONFIG_FILE)
