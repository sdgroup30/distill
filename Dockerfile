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

RUN useradd -m temp
USER temp

ENV PATH="/venv-distill/bin:$PATH"

RUN apt-get update && \
    apt-get install -y git && \
    pip3 install -r requirements.txt && \
    pip3 install markdown && \
    pip3 install md_mermaid && \
    pip3 install matplotlib && \
    pip3 install pdfkit && \
    pip3 install pandoc && \
    apt-get install -y pandoc



# set sublimate.py as the entrypoint
ENTRYPOINT ["python","./distill/distill.py"]
