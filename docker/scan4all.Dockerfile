FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    git \
    python3 \
    python3-pip \
    golang \
    libpcap-dev \
    nmap \
    curl \
    wget \
    && apt clean

# Clone scan4all repo
RUN git clone --depth 1 https://github.com/Arielpoghon/scan4all.git /opt/scan4all

WORKDIR /opt/scan4all

RUN go build -o /usr/local/bin/scan4all .

ENTRYPOINT ["/usr/local/bin/scan4all"]
