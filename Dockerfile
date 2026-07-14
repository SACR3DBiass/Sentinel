FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application
COPY . .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8000

CMD gunicorn app:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --timeout 180
