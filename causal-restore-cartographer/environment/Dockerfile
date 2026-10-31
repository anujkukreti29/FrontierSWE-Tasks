FROM python:3.12.16-slim-trixie@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
WORKDIR /app
COPY cartographer /app/cartographer
COPY PROTOCOL.md /app/PROTOCOL.md
COPY fixtures /app/fixtures
COPY public_check.py /app/public_check.py
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
CMD ["bash"]
