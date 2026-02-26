FROM python:3.11-slim

WORKDIR /app

# Copy package source
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -e .

# Default: run gh-workflow-hardener on mounted repo
ENTRYPOINT ["gh-workflow-hardener"]
CMD ["/repo"]
