from sanic import Sanic, request, response

from application.application import application_app
from opentelemetry import trace
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.context.context import Context
from opentelemetry.trace.status import Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.trace import SpanKind

server = Sanic(__name__)
server.blueprint(application_app)


@server.middleware('request')
async def request_started(request: request.Request):
    if trace.get_tracer_provider() is None:
        pass
    else:
        ctx = TraceContextTextMapPropagator().extract(request.headers)
        tracer = trace.get_tracer(instrumenting_module_name=__name__,
                                  tracer_provider=trace.get_tracer_provider())
        span = tracer.start_span(request.path,
                                 context=ctx,
                                 kind=SpanKind.SERVER)
        span.set_attributes({
            SpanAttributes.HTTP_METHOD: request.method,
            SpanAttributes.HTTP_TARGET: request.path,
            SpanAttributes.HTTP_URL: request.url,
            SpanAttributes.HTTP_HOST: request.host,
            SpanAttributes.HTTP_CLIENT_IP: request.ip,
            SpanAttributes.NET_PEER_IP: request.ip,
        })
        request.ctx.span = span
        context = Context()
        request.ctx.span_context = trace.set_span_in_context(span, context)


@server.middleware('response')
async def request_finished(req: request.Request, res: response.HTTPResponse):
    try:
        if trace.get_tracer_provider() is None:
            pass
        else:
            if req.ctx.span:
                req.ctx.span.set_attributes(
                    {SpanAttributes.HTTP_STATUS_CODE: res.status})
                if res.status == 200:
                    req.ctx.span.set_status(Status(StatusCode.OK))
                else:
                    req.ctx.span.set_status(Status(StatusCode.ERROR))
                req.ctx.span.end()
    except Exception as e:
        return response.json({"error": str(e)})


def init(app: Sanic, request_timeout, response_timeout):
    if app is None:
        return
    app.update_config({
        "REQUEST_TIMEOUT": request_timeout,
        "RESPONSE_TIMEOUT": response_timeout
    })
