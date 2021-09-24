FROM python:3

# Basic Setup, update system and install basic tools
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get upgrade -y && \
    apt-get install -y \
    ffmpeg \
    vim \
    wget \
    --no-install-recommends && \
    apt-get clean

# Copy _build and _run Files
COPY _build /_build/
COPY _run /_run/

# Move in run script
RUN cp /_build/run-cmd.sh /usr/bin/run

# Install chrome
RUN curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && \
	echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google.list && \
	apt-get update && apt-get install -y --no-install-recommends \
	    google-chrome-stable && \
    groupadd -r chrome && \
    mkdir -p /root/Downloads && \
    usermod -a -G chrome,audio,video root

    # groupadd -r chrome && \
    # useradd -r -g chrome -G audio,video chrome && \
    # mkdir -p /home/chrome/Downloads && \
    # chown -R chrome:chrome /home/chrome

# Run Chrome as non privileged user
#USER chrome

WORKDIR /app
COPY ./src/ /app

RUN pip install -r /app/requirements.txt

ENTRYPOINT ["run"]
