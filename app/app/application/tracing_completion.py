from collections import defaultdict
from log import logger

from .l7_flow_tracing import (L7_FLOW_RELATIONSHIP_SPAN_ID)
from .l7_flow_tracing import (L7FlowTracing)
from common.utils import inner_defaultdict_int

log = logger.getLogger(__name__)


class TracingCompletion(L7FlowTracing):

    def __init__(self, args, headers):
        super().__init__(args, headers)
        self.app_spans = [
            app_span.to_primitive() for app_span in self.args.app_spans
        ]
        self.update_time()
        self.complete_app_span(self.app_spans)

    async def query(self):
        max_iteration = self.args.get("max_iteration", 30)
        network_delay_us = self.args.get("network_delay_us")
        self.failed_regions = set()
        time_filter = f"time>={self.start_time} AND time<={self.end_time}"
        self.has_attributes = self.args.get("has_attributes", 0)
        base_filter = ''
        app_span_id = ''
        # get an related _id from app_spans with same trace_id
        for app_span in self.app_spans:
            trace_id = app_span.get("trace_id", "")
            app_span_id = app_span[
                "_id"]  # after `complete_app_span`, _id has been filled
            if trace_id:
                _id = await self.get_id_by_trace_id(trace_id, time_filter)
                if _id != "":
                    base_filter += f"_id = {_id}"
                else:
                    # when trace_id not found, we still need to `sort_all_flows` and `format_final_result` for app_spans
                    # so we use `1=0` filter to avoid query error
                    base_filter = "1=0"
                break
        self.args._id = app_span_id  # set app_span_id as args, make it never been pruning
        # build related_map inside app_spans
        related_map_from_api = defaultdict(inner_defaultdict_int)
        for i in range(len(self.app_spans)):
            for j in range(len(self.app_spans)):
                if i == j:
                    continue
                related_map_from_api[self.app_spans[i]['_id']][
                    self.app_spans[j]['_id']] |= L7_FLOW_RELATIONSHIP_SPAN_ID
        rst = await self.trace_l7_flow(
            time_filter,
            self.start_time,
            self.end_time,
            base_filter,
            max_iteration,
            network_delay_us,
            app_spans_from_api=self.app_spans,
            related_map_from_api=related_map_from_api)
        if not rst:
            return self.status, rst, self.failed_regions
        rst.pop("services", None)
        for res in rst.get("tracing", []):
            res.pop("selftime", None)
            res.pop("Enum(tap_side)", None)
            res.pop("id", None)
            res.pop("parent_id", None)
            res.pop("childs", None)
            res.pop("service_uid", None)
            res.pop("service_uname", None)
            res.pop("tap_port", None)
            res.pop("tap_port_name", None)
            res.pop("resource_from_vtap", None)
            res.pop("set_parent_info", None)
            res.pop("auto_instance", None)
        return self.status, rst, self.failed_regions

    # update start time and end time
    def update_time(self):
        min_time = 0
        max_time = 0
        for app_span in self.app_spans:
            start_time_s = int(app_span.get("start_time_us", 0) / 1000000)
            end_time_s = int(app_span.get("end_time_us", 0) / 1000000)
            if not min_time:
                min_time = start_time_s
            elif start_time_s < min_time:
                min_time = start_time_s
            if not max_time:
                max_time = end_time_s
            elif end_time_s > max_time:
                max_time = end_time_s
        self.start_time = min_time - 3
        self.end_time = max_time + 3
