FROM python:3.9-slim

LABEL description="Vulnerable Web Application for RedCell Training"

# Install dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application
COPY app.py /app/
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create uploads directory
RUN mkdir -p /tmp/uploads

# Expose port
EXPOSE 80

# Run application
CMD ["python", "app.py"]
