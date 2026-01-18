# Use slim image for smaller size
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (curl for healthchecks, libpq for postgres)
RUN apt-get update && apt-get install -y \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m appuser
WORKDIR /home/appuser/app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Chown all the files to the app user
RUN chown -R appuser:appuser /home/appuser/app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
