FROM python:3.9-slim-buster

# Update packages, install dependencies and tshark for PCAP parsing
RUN apt-get update;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autotools-dev autoconf make flex byacc git libtool pkg-config libbz2-dev tshark

# Install nfdump for FLOW parsing
RUN git clone https://github.com/phaag/nfdump.git /app/nfdump
WORKDIR /app/nfdump
RUN ./autogen.sh; ./configure; make; make install

# Install dissector python dependencies
COPY requirements.txt /app
RUN pip install -r /app/requirements.txt

COPY . /app
WORKDIR /app

ENTRYPOINT ["python", "src/main.py"]
