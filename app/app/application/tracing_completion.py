from collections import defaultdict
import pandas as pd
from pandas import DataFrame

from .l7_flow_tracing import (TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                              TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP,
                              TAP_SIDE_APP, RETURN_FIELDS)
from .l7_flow_tracing import (L7FlowTracing, L7NetworkMeta, L7SyscallMeta,
                              L7XrequestMeta)
from .l7_flow_tracing import sort_all_flows, format, set_all_relate
from common import const
from config import config
from models.models import AppSpans


class TracingCompletion(L7FlowTracing):

    def __init__(self, args, headers):
        super().__init__(args, headers)
        self.app_spans = [
            app_span.to_primitive() for app_span in self.args.app_spans
        ]
        self.update_time()
        self.complete_app_span(self.app_spans)
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
        query_simple_trace_id = False
        dataframe_flowmetas = self.app_spans_df
        if dataframe_flowmetas.empty:
            return {}
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
            new_trace_id_flows = pd.DataFrame()
            new_trace_id_filters = []
            # 主动注入的追踪信息
            if not allow_multiple_trace_ids_in_tracing_result and not trace_id:
                delete_index = []
                deleted_trace_ids = set()
                for index in range(len(dataframe_flowmetas.index)):
                    flow_trace_id = dataframe_flowmetas['trace_id'][index]
                    if flow_trace_id in [0, '']:
                        continue
                    if trace_id and trace_id != flow_trace_id:
                        delete_index.append(index)
                        deleted_trace_ids.add(flow_trace_id)
                    if not trace_id:
                        trace_id = flow_trace_id
                if trace_id and not query_simple_trace_id:
                    new_trace_id_filters.append(f"trace_id='{trace_id}'")
                    # Trace id query separately
                    new_trace_id_flows = await self.query_flowmetas(
                        time_filter, ' OR '.join(new_trace_id_filters))
                    if type(new_trace_id_flows) != DataFrame:
                        break
                    new_trace_id_flows.rename(columns={'_id_str': '_id'},
                                              inplace=True)
                    query_simple_trace_id = True
                if delete_index:
                    dataframe_flowmetas = dataframe_flowmetas.drop(
                        delete_index)
                    dataframe_flowmetas = dataframe_flowmetas.reset_index(
                        drop=True)
                    log.debug(f"删除的trace id为：{deleted_trace_ids}")
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
                    new_trace_id_filters.append('(' + ' OR '.join([
                        "trace_id='{tid}'".format(tid=tid)
                        for tid in trace_ids_set
                    ]) + ')')
                    # Trace id query separately
                    new_trace_id_flows = await self.query_flowmetas(
                        time_filter, ' OR '.join(new_trace_id_filters))
                    if type(new_trace_id_flows) != DataFrame:
                        break
                    new_trace_id_flows.rename(columns={'_id_str': '_id'},
                                              inplace=True)

            # 新的网络追踪信息
            new_network_metas = set()
            req_tcp_seqs = set()
            resp_tcp_seqs = set()
            for index in range(len(dataframe_flowmetas.index)):
                req_tcp_seq = dataframe_flowmetas['req_tcp_seq'][index]
                resp_tcp_seq = dataframe_flowmetas['resp_tcp_seq'][index]
                tap_side = dataframe_flowmetas['tap_side'][index]
                if req_tcp_seq == 0 and resp_tcp_seq == 0:
                    continue
                if tap_side not in [
                        TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                ] and tap_side not in const.TAP_SIDE_RANKS:
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
            for nnm in new_network_metas:
                req_tcp_seq = nnm[2]
                resp_tcp_seq = nnm[3]
                if req_tcp_seq:
                    req_tcp_seqs.add(str(req_tcp_seq))
                if resp_tcp_seq:
                    resp_tcp_seqs.add(str(resp_tcp_seq))
            # Network span relational query
            network_filters = []
            if req_tcp_seqs:
                network_filters.append(
                    f"req_tcp_seq IN ({','.join(req_tcp_seqs)})")
            if resp_tcp_seqs:
                network_filters.append(
                    f"resp_tcp_seq IN ({','.join(resp_tcp_seqs)})")
            if network_filters:
                filters.append(f"({' OR '.join(network_filters)})")

            # 新的系统调用追踪信息
            new_syscall_metas = set()
            syscall_trace_id_requests = set()
            syscall_trace_id_responses = set()
            for index in range(len(dataframe_flowmetas.index)):
                syscall_trace_id_request = dataframe_flowmetas[
                    'syscall_trace_id_request'][index]
                syscall_trace_id_response = dataframe_flowmetas[
                    'syscall_trace_id_response'][index]
                if syscall_trace_id_request > 0 or syscall_trace_id_response > 0:
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
            for nsm in new_syscall_metas:
                syscall_trace_id_request = nsm[2]
                syscall_trace_id_response = nsm[3]
                if syscall_trace_id_request > 0:
                    syscall_trace_id_requests.add(
                        str(syscall_trace_id_request))
                if syscall_trace_id_response > 0:
                    syscall_trace_id_responses.add(
                        str(syscall_trace_id_response))
            # System span relational query
            syscall_filters = []
            if syscall_trace_id_requests or syscall_trace_id_responses:
                syscall_filters.append(
                    f"syscall_trace_id_request IN ({','.join(list(syscall_trace_id_requests) + list(syscall_trace_id_responses))})"
                )
                syscall_filters.append(
                    f"syscall_trace_id_response IN ({','.join(list(syscall_trace_id_requests) + list(syscall_trace_id_responses))})"
                )
            if syscall_filters:
                filters.append(f"({' OR '.join(syscall_filters)})")

            new_x_request_metas = set()
            x_request_id_0s = set()
            x_request_id_1s = set()
            for index in range(len(dataframe_flowmetas.index)):
                x_request_id_0 = dataframe_flowmetas['x_request_id_0'][index]
                x_request_id_1 = dataframe_flowmetas['x_request_id_1'][index]
                if x_request_id_0 in [0, ''] and x_request_id_1 in [0, '']:
                    continue
                new_x_request_metas.add(
                    (dataframe_flowmetas['_id'][index],
                     dataframe_flowmetas['x_request_id_0'][index],
                     dataframe_flowmetas['x_request_id_1'][index]))
            new_x_request_metas -= x_request_metas
            x_request_metas |= new_x_request_metas
            xrequests = [L7XrequestMeta(nxr) for nxr in new_x_request_metas]
            for nxr in new_x_request_metas:
                x_request_id_0 = nxr[1]
                x_request_id_1 = nxr[2]
                if x_request_id_0:
                    x_request_id_0s.add(f"'{x_request_id_0}'")
                if x_request_id_1:
                    x_request_id_1s.add(f"'{x_request_id_1}'")
            # x_request_id related query
            x_request_filters = []
            if x_request_id_0s:
                x_request_filters.append(
                    f"x_request_id_1 IN ({','.join(x_request_id_0s)})")
            if x_request_id_1s:
                x_request_filters.append(
                    f"x_request_id_0 IN ({','.join(x_request_id_1s)})")
            if x_request_filters:
                filters.append(f"({' OR '.join(x_request_filters)})")

            new_flows = pd.DataFrame()
            if filters:
                # Non-trace_id relational queries
                new_flows = await self.query_flowmetas(time_filter,
                                                       ' OR '.join(filters))
                if type(new_flows) != DataFrame:
                    break
                new_flow_delete_index = []
                deleted_trace_ids = set()
                old_ids = set(dataframe_flowmetas['_id'])
                for index in range(len(new_flows.index)):
                    _id = new_flows['_id_str'][index]
                    flow_trace_id = new_flows['trace_id'][index]
                    # Delete different trace id data
                    if not allow_multiple_trace_ids_in_tracing_result:
                        if trace_id and flow_trace_id and trace_id != flow_trace_id:
                            new_flow_delete_index.append(index)
                            deleted_trace_ids.add(flow_trace_id)
                            continue
                    # delete dup _id for performance
                    if _id in old_ids:
                        new_flow_delete_index.append(index)
                if new_flow_delete_index:
                    new_flows = new_flows.drop(
                        new_flow_delete_index).reset_index(drop=True)
                if deleted_trace_ids:
                    log.debug(f"删除的trace id为：{deleted_trace_ids}")
                new_flows.rename(columns={'_id_str': '_id'}, inplace=True)

                new_related_map = defaultdict(list)
                if xrequests:
                    for x_request in xrequests:
                        x_request.set_relate(new_flows, new_related_map)

                if syscalls:
                    for syscall in syscalls:
                        syscall.set_relate(new_flows, new_related_map)

                if networks:
                    for network in networks:
                        network.set_relate(new_flows, new_related_map)

                new_flow_delete_index = []
                for index in range(len(new_flows.index)):
                    _id = new_flows['_id'][index]
                    # Delete unrelated data
                    if _id not in new_related_map:
                        new_flow_delete_index.append(index)
                if new_flow_delete_index:
                    new_flows = new_flows.drop(
                        new_flow_delete_index).reset_index(drop=True)

            # Merge all flows and check if any new flows are generated
            old_flows_length = len(dataframe_flowmetas)
            dataframe_flowmetas = pd.concat(
                [dataframe_flowmetas, new_flows, new_trace_id_flows],
                join="outer",
                ignore_index=True).drop_duplicates(["_id"
                                                    ]).reset_index(drop=True)
            # L7 Flow ID信息
            l7_flow_ids |= set(dataframe_flowmetas['_id'])
            new_flows_length = len(dataframe_flowmetas)
            if old_flows_length == new_flows_length:
                break
        set_all_relate(dataframe_flowmetas, related_map, network_delay_us)
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
            return {}
        l7_flows.rename(columns={'_id_str': '_id'}, inplace=True)
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
