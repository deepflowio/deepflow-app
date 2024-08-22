FROM python:3.8.19-slim-bullseye AS runner
RUN useradd -u 1000 -m deepflow -s /bin/bash && \
    chmod 777 $(which apt-get)
USER deepflow
ARG TARGETARCH
RUN apt-get update && apt-get upgrade -y
RUN pip install --upgrade --disable-pip-version-check --no-cache-dir pip setuptools
RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/output_${TARGETARCH}/* /usr/local  && \
    mkdir -p /etc/deepflow/  && \
    cp -a /tmp-mount/app.yaml /etc/deepflow/  && \
    cp -a /tmp-mount/app /  && \
    chmod -R 755 /app  && \
    chmod -R 755 /etc/deepflow/

CMD python3 -u /app/app.py
