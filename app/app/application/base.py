import uuid

from data.status import Status

# 0: unspecified, 1: internal, 2: server, 3: client, 4: producer, 5: consumer
TAP_SIDE_BY_SPAN_KIND = {
    0: "app",
    1: "app",
    2: "s-app",
    3: "c-app",
    4: "c-app",
    5: "s-app"
}


class Base(object):

    def __init__(self, args, headers):
        self.args = args
        self.start_time = int(self.args.get("time_start", 0))
        self.end_time = int(self.args.get("time_end", 0))
        self.headers = headers
        self.status = Status()
        self.region = self.args.get("region", None)

    # Completing application span attribute information
    def complete_app_span(self, app_spans):
        for i, app_span in enumerate(app_spans):
            tap_side_by_span_kind = TAP_SIDE_BY_SPAN_KIND.get(
                app_span.get('span_kind'))
            app_span["tap_side"] = tap_side_by_span_kind
            app_span.pop("span_kind", None)
            for tag_int in [
                    "type", "req_tcp_seq", "resp_tcp_seq", "l7_protocol",
                    "vtap_id", "protocol", "flow_id",
                    "syscall_trace_id_request", "syscall_trace_id_response",
                    "syscall_cap_seq_0", "tap_port_type",
                    "auto_instance_0_icon_id", "auto_instance_1_icon_id",
                    "auto_service_type_0", "response_status",
                    "auto_service_id_0", "auto_instance_id_1",
                    "auto_instance_type_0", "auto_service_id_1", "tap_port",
                    "response_duration", "auto_instance_id_0", "process_id_0",
                    "subnet_id_1", "auto_instance_type_1", "syscall_cap_seq_1",
                    "process_id_1", "response_code", "request_id",
                    "subnet_id_0", "auto_service_type_1", "tap_id"
            ]:
                app_span[tag_int] = 0 if not app_span.get(
                    tag_int) else app_span[tag_int]
            for tag_str in [
                    "x_request_id_0", "x_request_id_1", "auto_instance_0",
                    "auto_instance_1", "subnet_0", "app_service",
                    "_tsdb_region_name", "process_kname_0",
                    "http_proxy_client", "auto_instance_1_node_type",
                    "app_instance", "response_exception", "version",
                    "l7_protocol_str", "auto_instance_0_node_type",
                    "auto_service_0", "request_type", "request_domain", "ip_0",
                    "ip_1", "process_kname_1", "subnet_1", "request_resource",
                    "Enum(tap_side)", "tap_port_name", "endpoint",
                    "auto_service_1", "response_result", "tap"
            ]:
                app_span[tag_str] = "" if not app_span.get(
                    tag_str) else app_span[tag_str]
            app_span["resource_from_vtap"] = (0, 0, "", 0, 0, "")
            app_span["_id"] = uuid.uuid4(
            ).node if not app_span.get('_id') else app_span['_id']
