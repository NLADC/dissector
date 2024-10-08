# Multi-stage build
FROM rust:bookworm AS build

RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/NLADC/pcap-converter /var/tmp/pcap-converter
WORKDIR /var/tmp/pcap-converter

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autotools-dev autoconf make flex byacc git libtool pkg-config libbz2-dev

# Build pcap-converter
RUN cargo build --release

# Build and install nfdump
RUN git clone https://github.com/phaag/nfdump.git /app/nfdump
WORKDIR /app/nfdump
RUN ./autogen.sh && ./configure && make && make install && ldconfig


FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get upgrade -y;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark tcpdump

# copy pcap-converter and nfdump from build stage
COPY --from=build /var/tmp/pcap-converter/target/release/pcap-converter /usr/bin/pcap-converter
COPY --from=build /usr/local/bin/nfdump /usr/local/bin/
COPY --from=build /usr/local/lib/* /usr/local/lib/
RUN ldconfig

# Create user
#RUN adduser --system --group dissector
#USER dissector
WORKDIR /app

# Create venv and set ENV accordingly
ENV VIRTUAL_ENV=/app/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV HOME=/app
# update pip
RUN pip install --upgrade pip
# install wheel
RUN pip install wheel
# Install dissector dependencies
COPY requirements.txt /app
RUN pip install -r /app/requirements.txt
ENV DISSECTOR_DOCKER=1

# Copy the source files to the image
COPY src/ /app

# Copy entrypoint.sh to the image
COPY entrypoint.sh /app

# Ensure intermediate files are stored on disk rather than tmpfs/RAM (default for /tmp)
ENV TMPDIR=/var/tmp
ENTRYPOINT ["/app/entrypoint.sh", "/app/venv/bin/python", "main.py"]
