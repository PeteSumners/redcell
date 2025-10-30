FROM ubuntu:22.04

LABEL description="Internal High-Value Target for RedCell Training"

# Install tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Set up SSH
RUN mkdir /var/run/sshd
RUN echo 'root:InternalRoot2024!' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create sensitive data
RUN mkdir -p /data/sensitive
RUN echo "FLAG{internal_server_compromised}" > /data/sensitive/secret.txt
RUN echo "db_password=SuperSecretDBPass123" > /data/sensitive/config.txt

# Create internal user
RUN useradd -m -s /bin/bash internaluser && echo 'internaluser:internal123' | chpasswd

# Expose SSH
EXPOSE 22

# Run SSH daemon
CMD ["/usr/sbin/sshd", "-D"]
