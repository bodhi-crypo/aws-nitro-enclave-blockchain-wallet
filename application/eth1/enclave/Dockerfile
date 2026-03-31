FROM python:3.10-slim

WORKDIR /app

# Build this image with application/eth1 as the Docker build context.
COPY ./enclave/requirements.txt ./requirements.txt
RUN pip3 install -r /app/requirements.txt

COPY ./enclave/server.py ./server.py
COPY ./enclave/start.sh ./start.sh

RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
