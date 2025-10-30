FROM ubuntu:22.04

LABEL description="DMZ Pivot Host for RedCell Training"

# Install basic tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    python3 \
    python3-pip \
    curl \
    wget \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set up SSH
RUN mkdir /var/run/sshd
RUN echo 'root:weakpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create a regular user
RUN useradd -m -s /bin/bash dmzuser && echo 'dmzuser:password123' | chpasswd

# Expose SSH
EXPOSE 22

# Run SSH daemon
CMD ["/usr/sbin/sshd", "-D"]
