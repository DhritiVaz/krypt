# Use official Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements first (Docker caches this layer — faster rebuilds)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the app
CMD ["python", "run.py"]