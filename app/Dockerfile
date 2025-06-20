FROM python:3.8-alpine AS runner
ARG TARGETARCH
RUN apk update && apk upgrade && apk add --no-cache libstdc++
RUN pip install --upgrade --disable-pip-version-check --no-cache-dir pip setuptools
RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/output_${TARGETARCH}/* /usr/local && \
    mkdir -p /etc/deepflow/  && \
    cp -a /tmp-mount/app.yaml /etc/deepflow/  && \
    cp -a /tmp-mount/app /root/

CMD python3 -u /root/app/app.py
