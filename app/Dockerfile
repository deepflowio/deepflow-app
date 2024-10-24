FROM alpine:3.20.3 AS runner

ARG TARGETARCH

RUN apk update && apk upgrade
RUN apk add --no-cache curl jq shadow gcc patch libffi-dev zlib-dev bzip2-dev openssl-dev ncurses-dev sqlite-dev readline-dev gdbm-dev libpcap-dev xz-dev build-base
RUN wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz  && \
    tar xf Python-3.8.12.tgz
RUN cd Python-3.8.12  && \
    ./configure  && \
    make && make install
RUN ln -s /usr/local/bin/python3 /usr/local/bin/python
RUN curl -s https://bootstrap.pypa.io/get-pip.py -o /get-pip.py  && \
    python get-pip.py
RUN pip install --upgrade --disable-pip-version-check --no-cache-dir --break-system-packages setuptools
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
