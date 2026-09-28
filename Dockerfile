FROM python:3.14-alpine@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --chown=65532:65532 app/server.py /app/server.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "/app/server.py"]
