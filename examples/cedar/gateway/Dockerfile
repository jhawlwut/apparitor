# Two stages: build the official Cedar CLI, then run the stdlib gateway alongside it.
# The build stage needs network egress (cargo fetches the pinned crate); the runtime is
# offline. Build context is examples/cedar/ so the vendored policies + entities are copied.

FROM rust:1-slim AS cedar
RUN cargo install cedar-policy-cli --version 4.11.0 --locked

FROM python:3.12-slim
COPY --from=cedar /usr/local/cargo/bin/cedar /usr/local/bin/cedar
WORKDIR /app
COPY gateway/gateway.py ./gateway.py
COPY policies.cedar entities.json ./
EXPOSE 8080
ENTRYPOINT ["python", "gateway.py", "--port", "8080", \
            "--policies", "policies.cedar", "--entities", "entities.json"]
