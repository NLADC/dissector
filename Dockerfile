FROM python:3.9-slim-buster

RUN apt-get update;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autotools-dev autoconf make flex byacc git libtool pkg-config libbz2-dev tshark

# Install nfdump
RUN git clone https://github.com/phaag/nfdump.git /app/nfdump
WORKDIR /app/nfdump
RUN ./autogen.sh; ./configure; make; make install

# Install dissector dependencies
COPY ddos_dissector.py /app
COPY requirements.txt /app
WORKDIR /app
RUN pip install -r requirements.txt

ENTRYPOINT ["python", "ddos_dissector.py"]
