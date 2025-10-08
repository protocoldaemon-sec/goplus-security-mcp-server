# Use Python 3.12 Alpine image
FROM python:3.12-alpine

# Install system dependencies
RUN apk add --no-cache \
    build-base \
    curl \
    && rm -rf /var/cache/apk/*

# Install uv
RUN pip install uv

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml ./

# Install dependencies using pip instead of uv for better compatibility
RUN pip install --no-cache-dir \
    mcp>=1.15.0 \
    requests>=2.31.0 \
    pydantic>=2.0.0 \
    fastapi>=0.104.0 \
    uvicorn>=0.24.0 \
    starlette>=0.27.0

# Copy source code
COPY . .

# Set transport mode to HTTP
ENV TRANSPORT=http

# Expose port
EXPOSE 8081

# Run the application
CMD ["python", "main.py"]
