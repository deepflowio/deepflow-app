from collections import defaultdict
import pandas as pd
from pandas import DataFrame

from .l7_flow_tracing import (TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                              TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP,
                              TAP_SIDE_APP, RETURN_FIELDS)
from .l7_flow_tracing import (L7FlowTracing, L7NetworkMeta, L7SyscallMeta,
                              L7AppMeta, L7XrequestMeta)
from .l7_flow_tracing import sort_all_flows, format
from common import const
from config import config

# 0: unspecified, 1: internal, 2: server, 3: client, 4: producer, 5: consumer
TAP_SIDE_BY_SPAN_KIND = {
    0: "app",
    1: "app",
    2: "s-app",
    3: "c-app",
    4: "c-app",
    5: "s-app"
}


class TracingCompletion(L7FlowTracing):
    def __init__(self, args, headers):
        super().__init__(args, headers)
        self.app_spans = [
            app_span.to_primitive() for app_span in self.args.app_spans
        ] if not isinstance(self.args.app_spans, list) else self.args.app_spans
        self.update_time()
        self.complete_app_span()
        self.app_spans_df = pd.DataFrame(self.app_spans)

    async def query(self):
        max_iteration = self.args.get("max_iteration", 30)
        network_delay_us = self.args.get("network_delay_us")
        ntp_delay_us = self.args.get("ntp_delay_us", 10000)
        self.failed_regions = set()
        time_filter = f"time>={self.start_time} AND time<={self.end_time}"
        self.has_attributes = self.args.get("has_attributes", 0)
        rst = await self.trace_l7_flow(time_filter=time_filter,
                                       base_filter='',
                                       return_fields=["related_ids"],
                                       max_iteration=max_iteration,
                                       network_delay_us=network_delay_us,
                                       ntp_delay_us=ntp_delay_us)
        if not rst:
            return self.status, rst, self.failed_regions
        if not config.call_apm_api_to_supplement_trace:
            rst.pop("services", None)
            for res in rst.get("tracing", []):
                res.pop("selftime", None)
                res.pop("Enum(tap_side)", None)
                res.pop("attribute", None)
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

    async def trace_l7_flow(self,
                            time_filter: str,
                            base_filter: str,
                            return_fields: list,
                            max_iteration: int = 30,
                            network_delay_us: int = config.network_delay_us,
                            ntp_delay_us: int = 10000) -> list:
        """L7 FlowLog 追踪入口

        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        return_fields: 返回l7_flow_log的哪些字段
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        """
        network_metas = set()
        syscall_metas = set()
        trace_ids = set()
        app_metas = set()
        x_request_metas = set()
        l7_flow_ids = set()
        xrequests = []
        related_map = defaultdict(list)
        dataframe_flowmetas = self.app_spans_df
        if dataframe_flowmetas.empty:
            return []
        for i in range(len(self.app_spans)):
            for j in range(len(self.app_spans)):
                if i == j:
                    continue
                related_map[dataframe_flowmetas['_id'][i]].append(
                    str(dataframe_flowmetas['_id'][j]) + "-app")

        trace_id = ''
        allow_multiple_trace_ids_in_tracing_result = config.allow_multiple_trace_ids_in_tracing_result
        for i in range(max_iteration):
            if type(dataframe_flowmetas) != DataFrame:
                break
            filters = []

            # 主动注入的追踪信息
            if not allow_multiple_trace_ids_in_tracing_result and not trace_id:
                delete_index = []
                for index in range(len(dataframe_flowmetas.index)):
                    if dataframe_flowmetas['trace_id'][index] in [0, '']:
                        continue
                    if trace_id and trace_id != dataframe_flowmetas[
                            'trace_id'][index]:
                        delete_index.append(index)
                    trace_id = dataframe_flowmetas['trace_id'][index]
                    continue
                dataframe_flowmetas = dataframe_flowmetas.drop(delete_index)
            else:
                new_trace_ids = set()
                for index in range(len(dataframe_flowmetas.index)):
                    if dataframe_flowmetas['trace_id'][index] in [0, '']:
                        continue
                    new_trace_ids.add((dataframe_flowmetas['_id'][index],
                                       dataframe_flowmetas['trace_id'][index]))
                new_trace_ids -= trace_ids
                trace_ids |= new_trace_ids
                if new_trace_ids:
                    trace_ids_set = set([nxrid[1] for nxrid in new_trace_ids])
                    filters.append('(' + ' OR '.join([
                        "trace_id='{tid}'".format(tid=tid)
                        for tid in trace_ids_set
                    ]) + ')')

            # 新的网络追踪信息
            new_network_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['req_tcp_seq'][index] == 0 \
                        and dataframe_flowmetas['resp_tcp_seq'][index] == 0:
                    continue
                if dataframe_flowmetas['tap_side'][index] not in [
                        TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                ] and dataframe_flowmetas['tap_side'][
                        index] not in const.TAP_SIDE_RANKS:
                    continue
                new_network_metas.add((
                    dataframe_flowmetas['_id'][index],
                    dataframe_flowmetas['type'][index],
                    dataframe_flowmetas['req_tcp_seq'][index],
                    dataframe_flowmetas['resp_tcp_seq'][index],
                    dataframe_flowmetas['start_time_us'][index],
                    dataframe_flowmetas['end_time_us'][index],
                    dataframe_flowmetas['span_id'][index],
                    dataframe_flowmetas['x_request_id_0'][index],
                    dataframe_flowmetas['x_request_id_1'][index],
                ))
            new_network_metas -= network_metas
            network_metas |= new_network_metas
            networks = [
                L7NetworkMeta(nnm, network_delay_us)
                for nnm in new_network_metas
            ]
            if networks:
                networks_tuple_map = {
                    network.to_tuple(): network
                    for network in networks
                }
                networks_filters = '((' + ' OR '.join([
                    networks_tuple_map[nnm].to_sql_filter()
                    for nnm in set(list(networks_tuple_map.keys()))
                ]) + ')' + ' AND (resp_tcp_seq!=0 OR req_tcp_seq!=0))'
                filters.append(networks_filters)

            # 新的系统调用追踪信息
            new_syscall_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['syscall_trace_id_request'][index] > 0 or \
                        dataframe_flowmetas['syscall_trace_id_response'][
                            index] > 0:
                    new_syscall_metas.add((
                        dataframe_flowmetas['_id'][index],
                        dataframe_flowmetas['vtap_id'][index],
                        dataframe_flowmetas['syscall_trace_id_request'][index],
                        dataframe_flowmetas['syscall_trace_id_response']
                        [index],
                        dataframe_flowmetas['tap_side'][index],
                        dataframe_flowmetas['start_time_us'][index],
                        dataframe_flowmetas['end_time_us'][index],
                    ))
            new_syscall_metas -= syscall_metas
            syscall_metas |= new_syscall_metas
            syscalls = [L7SyscallMeta(nsm) for nsm in new_syscall_metas]
            if syscalls:
                syscalls_tuple_map = {
                    syscall.to_tuple(): syscall
                    for syscall in syscalls
                }
                syscall_filters = '(' + ' OR '.join([
                    syscalls_tuple_map[nsm].to_sql_filter()
                    for nsm in set(list(syscalls_tuple_map.keys()))
                ]) + ')'
                filters.append(syscall_filters)

            # 新的应用span追踪信息
            new_app_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['tap_side'][index] not in [
                        TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                        TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
                ] or not dataframe_flowmetas['span_id'][index]:
                    continue
                if type(dataframe_flowmetas['span_id'][index]) == str and \
                        dataframe_flowmetas['span_id'][index] and \
                        type(dataframe_flowmetas['parent_span_id'][
                                 index]) == str and \
                        dataframe_flowmetas['parent_span_id'][index]:
                    new_app_metas.add(
                        (dataframe_flowmetas['_id'][index],
                         dataframe_flowmetas['tap_side'][index],
                         dataframe_flowmetas['span_id'][index],
                         dataframe_flowmetas['parent_span_id'][index]))
            new_app_metas -= app_metas
            app_metas |= new_app_metas
            apps = [L7AppMeta(nam) for nam in new_app_metas]
            if apps:
                apps_tuple_map = {app.to_tuple(): app for app in apps}
                app_filters = '(' + ' OR '.join([
                    apps_tuple_map[nam].to_sql_filter()
                    for nam in set(list(apps_tuple_map.keys()))
                ]) + ')'
                filters.append(app_filters)

            new_x_request_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['x_request_id_0'][index] in [
                        0, ''
                ] and dataframe_flowmetas['x_request_id_1'][index] in [0, '']:
                    continue
                new_x_request_metas.add(
                    (dataframe_flowmetas['_id'][index],
                     dataframe_flowmetas['x_request_id_0'][index],
                     dataframe_flowmetas['x_request_id_1'][index]))
            new_x_request_metas -= x_request_metas
            x_request_metas |= new_x_request_metas
            x_requests = [L7XrequestMeta(nxr) for nxr in new_x_request_metas]
            if x_requests:
                x_requests_tuple_map = {
                    x_request.to_tuple(): x_request
                    for x_request in x_requests
                }
                x_request_filters = '(' + ' OR '.join([
                    x_requests_tuple_map[xrm].to_sql_filter()
                    for xrm in set(list(x_requests_tuple_map.keys()))
                ]) + ')'
                filters.append(x_request_filters)

            if not filters:
                break

            if not allow_multiple_trace_ids_in_tracing_result and trace_id:
                new_filters = []
                new_filters.append(f"({'OR '.join(filters)})")
                new_filters.append(f"(trace_id='{trace_id}' OR trace_id='')")
                new_flows = await self.query_flowmetas(
                    time_filter, ' AND '.join(new_filters))
            else:
                new_flows = await self.query_flowmetas(time_filter,
                                                       ' OR '.join(filters))
            if type(new_flows) != DataFrame:
                break
            # L7 Flow ID信息
            l7_flow_ids |= set(dataframe_flowmetas['_id'])

            len_of_flows = len(l7_flow_ids)

            if xrequests:
                for x_request in xrequests:
                    x_request.set_relate(new_flows, related_map)

            if syscalls:
                for syscall in syscalls:
                    syscall.set_relate(new_flows, related_map)

            if networks:
                for network in networks:
                    network.set_relate(new_flows, related_map)

            if apps:
                for app in apps:
                    app.set_relate(new_flows, related_map)
            dataframe_flowmetas = pd.concat([dataframe_flowmetas, new_flows],
                                            join="outer",
                                            ignore_index=True).drop_duplicates(
                                                ["_id"]).reset_index(drop=True)
            if len(set(dataframe_flowmetas['_id'])) - len_of_flows < 1:
                break
        # 获取追踪到的所有应用流日志
        return_fields += RETURN_FIELDS
        flow_fields = list(RETURN_FIELDS)
        if self.has_attributes:
            return_fields.append("attribute")
            flow_fields.append("attribute")
        l7_flows = pd.DataFrame([])
        if l7_flow_ids:
            l7_flows = await self.query_all_flows(time_filter, l7_flow_ids,
                                                  flow_fields)
        if type(l7_flows) != DataFrame:
            return []
        # Merge Incoming App Spans
        l7_flows = pd.concat([l7_flows, self.app_spans_df],
                             join="outer",
                             ignore_index=True).reset_index(drop=True)
        l7_flows.insert(0, "related_ids", "")
        l7_flows = l7_flows.where(l7_flows.notnull(), None)
        for index in range(len(l7_flows.index)):
            l7_flows["related_ids"][index] = related_map[l7_flows._id[index]]
        # 对所有应用流日志排序
        l7_flows_merged, app_flows, networks = sort_all_flows(
            l7_flows, network_delay_us, return_fields, ntp_delay_us)
        return format(l7_flows_merged, networks, app_flows,
                      self.args.get('_id'), network_delay_us)

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

    # Completing application span attribute information
    def complete_app_span(self):
        for i, app_span in enumerate(self.app_spans):
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
            app_span["_id"] = i
