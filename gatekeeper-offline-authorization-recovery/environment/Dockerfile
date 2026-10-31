FROM python:3.12-slim@sha256:6b25cbe6577518889d553cdd5a5da97d259348d8f6e45b527dd731caaba27a07
WORKDIR /workspace
RUN python -m pip install --no-cache-dir cryptography==46.0.4 cffi==2.0.0 pycparser==3.0
COPY workspace/ /workspace/
ENV PYTHONPATH=/workspace PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/bin/bash"]
