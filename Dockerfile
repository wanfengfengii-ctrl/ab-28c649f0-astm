# ASTM 会话审计服务：零第三方依赖，仅需 Python 标准库。
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

# 容器自带健康检查，供 Compose 的 service_healthy 依赖使用。
HEALTHCHECK --interval=2s --timeout=2s --start-period=1s --retries=15 \
  CMD ["python", "scripts/healthcheck.py"]

EXPOSE 8080

CMD ["python", "-m", "app.server"]
