# Base image pinned by digest. Validate the build on the target worker.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
WORKDIR /app
RUN pip install --no-cache-dir cryptography==44.0.2
COPY workspace/ /app/
ENV PYTHONPATH=/app
CMD ["bash"]
