FROM python:3.8-slim-buster AS runner
ARG TARGETARCH
RUN apt-get update && apt-get upgrade -y
RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/output_${TARGETARCH}/* /usr/local && \
    mkdir -p /etc/deepflow/  && \
    cp -a /tmp-mount/app.yaml /etc/deepflow/  && \
    cp -a /tmp-mount/app /root/

CMD python3 -u /root/app/app.py
