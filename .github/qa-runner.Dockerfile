FROM python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Candidate project runtime dependencies required by the trusted test suites.
# Pin exact versions so Candidate code cannot choose its own execution stack.
RUN python -m pip install --no-cache-dir \
    PyYAML==6.0.2 \
    jsonschema==4.23.0
