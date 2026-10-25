# xray binary from a multi-arch image (amd64, arm64, armv7, ...); bump both tags together with compose.yaml
FROM teddysun/xray:26.10.17 AS xray

FROM python:3.12-alpine
RUN apk add --no-cache curl iputils-ping
COPY --from=xray /usr/bin/xray /usr/local/bin/xray
COPY src/*.py /app/
WORKDIR /app
ENV PYTHONUNBUFFERED=1
# state.json is written after every cycle; a full search over a big subscription can take ~40 min
HEALTHCHECK --interval=300s --timeout=10s --start-period=3600s --retries=2 \
  CMD python3 -c "import os,sys,time; sys.exit(time.time() - os.path.getmtime('/data/state.json') > 3600)"
ENTRYPOINT ["python3", "/app/manager.py"]
CMD ["run"]
