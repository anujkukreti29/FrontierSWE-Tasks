FROM python:3.12.16-slim-trixie@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
WORKDIR /tests
COPY . /tests/
RUN mkdir -p /app/cartographer /logs/verifier && useradd --uid 10001 --create-home --shell /usr/sbin/nologin cand && chmod -R go-rwx /tests
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
CMD ["bash"]
