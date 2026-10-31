FROM python:3.12-slim@sha256:6b25cbe6577518889d553cdd5a5da97d259348d8f6e45b527dd731caaba27a07
WORKDIR /tests
RUN python -m pip install --no-cache-dir cryptography==46.0.4 cffi==2.0.0 pycparser==3.0
COPY . /tests/
RUN mkdir -p /workspace/gatekeeper /logs/verifier && chmod 0755 /workspace /workspace/gatekeeper && chmod -R go-rwx /tests && chmod 0700 /logs/verifier && chmod 0700 /tests && chmod +x /tests/test.sh
ENV PYTHONPATH=/workspace PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/bin/bash"]
