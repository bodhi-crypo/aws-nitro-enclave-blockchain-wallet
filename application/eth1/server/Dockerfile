FROM python:3.11-slim

WORKDIR /usr/src/app

# Build this image with application/eth1 as the Docker build context.
COPY ./server/app.py ./app.py
COPY ./server/requirements.txt ./requirements.txt

RUN pip3 install -r /usr/src/app/requirements.txt

ENV PORT=8080

CMD ["python", "./app.py"]
