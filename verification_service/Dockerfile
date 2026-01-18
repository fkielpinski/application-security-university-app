FROM python:3.11-slim

# Install system dependencies for psycopg2 and curl for healthcheck
RUN apt-get update && apt-get install -y \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m appuser

WORKDIR /home/appuser/app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set ownership
RUN chown -R appuser:appuser /home/appuser/app

USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
