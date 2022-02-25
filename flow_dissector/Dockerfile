FROM python:3.9-slim-buster

# Install nfdump
RUN git clone https://github.com/phaag/nfdump.git /app/nfdump
WORKDIR /app/nfdump
RUN ./autogen.sh; ./configure; make; make install

# Install dissector dependencies
COPY requirements.txt /app
RUN pip install -r /app/requirements.txt

COPY . /app
WORKDIR /app

ENTRYPOINT ["python", "src/main.py"]
