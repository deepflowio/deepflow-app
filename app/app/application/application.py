from sanic import Blueprint
from sanic.response import json as Response
from log import logger

from common.utils import json_response, format_response, app_exception, curl_perform
from common.const import API_PREFIX, HTTP_OK

from config import config
from .l7_flow_tracing import L7FlowTracing
from .tracing_completion import TracingCompletion
from models.models import FlowLogL7Tracing, TracingCompletionByExternalAppSpans

log = logger.getLogger(__name__)

application_app = Blueprint(str(__name__).replace(".", "_"))


@application_app.route(API_PREFIX + '/querier' + '/L7FlowTracing',
                       methods=['POST'])
@app_exception
async def application_log_l7_tracing(request):
    args = FlowLogL7Tracing(request.json)
    args.validate()

    status, response, failed_regions = await L7FlowTracing(
        args, request.headers).query()
    response_dict, code = format_response("Flow_Log_L7_Tracing", status,
                                          response, args.debug, failed_regions)
    return Response(json_response(**response_dict),
                    content_type='application/json; charset=utf-8',
                    status=code)


@application_app.route(API_PREFIX + '/querier' +
                       '/tracing-completion-by-external-app-spans',
                       methods=['POST'])
@app_exception
async def l7_flow_app_tracing(request):
    args = TracingCompletionByExternalAppSpans(request.json)
    args.validate()
    status, response, failed_regions = await TracingCompletion(
        args, request.headers).query()
    response_dict, code = format_response(
        "tracing-completion-by-external-app-spans", status, response,
        args.debug, failed_regions)
    return Response(json_response(**response_dict),
                    content_type='application/json; charset=utf-8',
                    status=code)
