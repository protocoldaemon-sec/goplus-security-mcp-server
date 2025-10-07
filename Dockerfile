FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies directly
RUN pip install --no-cache-dir \
    mcp>=1.15.0 \
    smithery>=0.4.2 \
    requests>=2.31.0 \
    pydantic>=2.0.0 \
    fastapi>=0.104.0 \
    uvicorn>=0.24.0

# Copy source code and main.py
COPY src/ .
COPY main.py .

# Make main.py executable
RUN chmod +x main.py

# Expose port
EXPOSE 8081

# Start the server
CMD ["python", "main.py"]
