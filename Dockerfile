# Small, current Python base.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first, in their own layer, so Docker caches them
# and doesn't reinstall on every code change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY scanner/ ./scanner/

# `docker run <image>` runs the zero-setup demo by default.
# Override args, e.g.: docker run --rm aws-cis-scanner --output json
ENTRYPOINT ["python", "-m", "scanner.cli"]
CMD ["--demo"]