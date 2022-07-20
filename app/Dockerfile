# 构建层
FROM python:3.8-slim-buster AS builder
RUN apt-get update && \
    apt-get install --no-install-suggests \
    --no-install-recommends --yes \
    gcc \
    libpython3-dev \
    libpq-dev \
    default-libmysqlclient-dev \
    make \
    && \
    pip install --upgrade pip

# Base 构建层
FROM builder AS builder-base
RUN pip install cffi 

# 自定义构建层
FROM builder-base AS builder-custom
RUN pip install --user  --disable-pip-version-check \
     	 --no-cache-dir \
         aiofiles==0.6.0 aiohttp==3.4.4 aiomysql==0.0.19 aioredis==1.3.1 \
         aiosqlite==0.16.1 async-timeout==3.0.1 asynctest==0.12.2 attrs==20.3.0 \
         certifi==2021.10.8 chardet==3.0.4 ciso8601==2.1.3 \
         cryptography==3.4.6 \
         Flask==0.11.1 httptools==0.3.0 idna==2.8 \
         ipaddr==2.2.0 ipaddress==1.0.23 IPy==1.1 itsdangerous==1.1.0 Jinja2==2.11.3 \
         MarkupSafe==1.1.1 multidict==4.7.6 netaddr==0.7.19 numpy==1.21.2 \
         pandas==1.3.3 pycparser==2.21 PyPika==0.47.7 python-dateutil==2.8.1 \
         pytz==2021.1 PyYAML==3.13 requests==2.22.0 sanic==18.12.0 schematics==2.1.0 setuptools==56.0.0 simplejson==3.5.3 \
         six==1.15.0 typing-extensions==3.10.0.2 tzlocal==2.1 \
         ujson==1.35 urllib3==1.25.11 uvloop==0.14.0 websockets==6.0 Werkzeug==1.0.1 yarl==1.3.0 \
         opentelemetry-sdk==1.11.1

FROM python:3.8-slim-buster AS runner
COPY --from=builder-custom /root/.local /usr/local
# Copy code
COPY ./app.yaml /etc/deepflow/
COPY ./app/ /root/app/

CMD python3 -u /root/app/app.py
