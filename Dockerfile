# syntax=docker/dockerfile:1

# ^^^ Must be first line to work

# Use basic python image
FROM python:3.8-slim-buster

# Create dir
WORKDIR /distill

# Add user

# Copy over the requirements for pip
COPY requirements.txt requirements.txt

# install the required packages

# Copy everything for sublimate to the container image
#COPY /.trivium /home/temp/.trivium

# Create the venv
RUN python3 -m venv venv-distill

ENV VIRTUAL_ENV=/venv-distill
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN apt-get update && \
    apt-get install -y git && \
    pip3 install -r requirements.txt

RUN useradd -m temp
USER temp


# set sublimate.py as the entrypoint
ENTRYPOINT ["/venv-distill/bin/distill"]
