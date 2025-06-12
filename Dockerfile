FROM python:3.12-slim
RUN mkdir -p /app
COPY block_ip.sh /app/block_ip.sh
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "ntop_auto_blocker.py"]
