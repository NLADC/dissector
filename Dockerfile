FROM python:3.9-slim-buster

RUN apt-get update && apt-get upgrade -y;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autotools-dev autoconf make flex byacc git libtool pkg-config libbz2-dev tshark

# Install nfdump
RUN git clone https://github.com/phaag/nfdump.git /app/nfdump
WORKDIR /app/nfdump
RUN ./autogen.sh && ./configure && make && make install && ldconfig

# Install dissector dependencies
COPY requirements.txt /app
RUN pip install --upgrade pip
RUN pip install -r /app/requirements.txt
ENV DISSECTOR_DOCKER=1

COPY src/ /app
WORKDIR /app

ENTRYPOINT ["python", "main.py"]
