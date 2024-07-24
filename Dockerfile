# Multi-stage build
# Build pcap-converter first
FROM rust:bookworm AS build

# RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/NLADC/pcap-converter /tmp/pcap-converter
WORKDIR /tmp/pcap-converter
RUN cargo build --release


FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get upgrade -y;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autotools-dev autoconf make flex byacc git libtool pkg-config libbz2-dev tshark tcpdump

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

# copy pcap-converter from build stage
COPY --from=build /tmp/pcap-converter/target/release/pcap-converter /usr/bin/pcap-converter

ENTRYPOINT ["python", "main.py"]
