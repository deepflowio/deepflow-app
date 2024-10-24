FROM alpine:3.20.3 AS runner

ARG TARGETARCH

RUN apk update && apk upgrade
RUN apk add --update --no-cache curl jq shadow py3-configobj py3-pip py3-setuptools python3 python3-dev
RUN pip install --upgrade --disable-pip-version-check --no-cache-dir --break-system-packages pip setuptools
RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/output_${TARGETARCH}/* /usr/local  && \
    mkdir -p /etc/deepflow/  && \
    cp -a /tmp-mount/app.yaml /etc/deepflow/  && \
    cp -a /tmp-mount/app /  && \
    chmod -R 755 /app  && \
    chmod -R 755 /etc/deepflow/  && \
    chown -R deepflow:deepflow /usr/local/lib/python3.8/
RUN useradd -u 1000 -m deepflow -s /bin/bash
RUN echo 'root:deepflow' | chpasswd

USER deepflow

CMD python3 -u /app/app.py
