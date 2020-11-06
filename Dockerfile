FROM debian:latest
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
WORKDIR /app_saos
COPY . /app_saos
RUN pip3 install -r requirements.txt
CMD ["python3", "application.py"]