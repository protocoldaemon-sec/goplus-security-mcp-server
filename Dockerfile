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
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --locked --no-dev

# Copy source code
COPY . .

# Install the project
RUN uv sync --locked --no-dev

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Set transport mode to HTTP
ENV TRANSPORT=http

# Expose port
EXPOSE 8081

# Run the application
CMD ["python", "main.py"]
