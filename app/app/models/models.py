from schematics.models import Model
from schematics.types import IntType, StringType, BooleanType
from schematics.types.compound import ListType, ModelType

from config import config

SPAN_KIND = [0, 1, 2, 3, 4, 5]


class FlowLogL7Tracing(Model):
    region = StringType(serialized_name="REGION", required=False)
    time_start = IntType(serialized_name="TIME_START",
                         required=True,
                         min_value=0)
    time_end = IntType(serialized_name="TIME_END", required=True, min_value=0)
    has_attributes = IntType(serialized_name="has_attributes", default=0)
    database = StringType(serialized_name="DATABASE", required=True)
    table = StringType(serialized_name="TABLE", required=True)
    _id = StringType(serialized_name="_id")
    trace_id = StringType(serialized_name="trace_id")
    debug = BooleanType(serialized_name="DEBUG", required=False)
    max_iteration = IntType(serialized_name="MAX_ITERATION",
                            required=False,
                            min_value=1,
                            default=config.max_iteration)
    network_delay_us = IntType(serialized_name="NETWORK_DELAY_US",
                               required=False,
                               min_value=1,
                               default=config.network_delay_us)
    ntp_delay_us = IntType(serialized_name="NTP_DELAY_US",
                           required=False,
                           min_value=1,
                           default=10000)
    signal_sources = ListType(StringType,
                              serialized_name="SIGNAL_SOURCES",
                              min_size=1,
                              required=False)


class AppSpans(Model):
    start_time_us = IntType(serialized_name="start_time_us",
                            required=True,
                            min_value=0)
    end_time_us = IntType(serialized_name="end_time_us",
                          required=True,
                          min_value=0)
    span_kind = IntType(serialized_name="span_kind",
                        required=True,
                        choices=SPAN_KIND)
    trace_id = StringType(serialized_name="trace_id", required=True)
    span_id = StringType(serialized_name="span_id", required=True)
    parent_span_id = StringType(serialized_name="parent_span_id",
                                required=True)


class TracingCompletionByExternalAppSpans(Model):
    app_spans = ListType(ModelType(AppSpans),
                         serialized_name="APP_SPANS",
                         min_size=1,
                         required=True)
    max_iteration = IntType(serialized_name="MAX_ITERATION",
                            required=False,
                            min_value=1,
                            default=30)
    network_delay_us = IntType(serialized_name="NETWORK_DELAY_US",
                               required=False,
                               min_value=1,
                               default=config.network_delay_us)
    debug = BooleanType(serialized_name="DEBUG", required=False)
    signal_sources = ListType(StringType,
                              serialized_name="SIGNAL_SOURCES",
                              min_size=1,
                              required=False)
