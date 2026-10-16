FROM python:3.11-slim
WORKDIR /app
COPY src/ /app/src/
COPY scripts/start_public_demo.py /app/scripts/start_public_demo.py
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1 PORT=7860
EXPOSE 7860
CMD ["python", "scripts/start_public_demo.py"]
