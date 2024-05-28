from sanic import Sanic

from application.application import application_app

server = Sanic(__name__)
server.blueprint(application_app)


@server.middleware('request')
async def request_started(request):
    pass


@server.middleware('response')
async def request_finished(request, response):
    pass


def init(app: Sanic, request_timeout, response_timeout):
    if app is None:
        return
    app.update_config({
        "REQUEST_TIMEOUT": request_timeout,
        "RESPONSE_TIMEOUT": response_timeout
    })