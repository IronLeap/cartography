FROM ubuntu:bionic

WORKDIR /srv/cartography

ENV PATH=/venv/bin:$PATH
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential python3.8-dev python3-pip python3-setuptools openssl libssl-dev gcc pkg-config libffi-dev libxml2-dev libxmlsec1-dev curl unzip wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY ./test-requirements.txt /srv/cartography/test-requirements.txt
COPY ./requirements.txt /srv/cartography/requirements.txt

# Installs pip supported by python3.8
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3.8 get-pip.py

RUN pip install -r requirements.txt && \
    pip install -r test-requirements.txt

ARG BUILDARCH
RUN if [ "$BUILDARCH" = "arm64" ]; \
    then \
      wget -q https://github.com/projectdiscovery/nuclei/releases/download/v2.9.4/nuclei_2.9.4_linux_arm64.zip -O nuclei.zip; \
    else \
      wget -q https://github.com/projectdiscovery/nuclei/releases/download/v2.9.4/nuclei_2.9.4_linux_amd64.zip -O nuclei.zip; \
    fi \
    && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip
    
COPY . /srv/cartography
