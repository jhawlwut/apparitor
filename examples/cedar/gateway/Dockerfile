# Two stages: build the official Cedar CLI, then run the stdlib gateway alongside it.
# The build stage needs network egress (cargo fetches the pinned crate); the runtime is
# offline. Build context is examples/cedar/ so the vendored policies + entities are copied.

FROM rust:1-slim@sha256:26abcef3d79b8d890c4ceb17093154573e1f6479cf6dd7c1450043b8458350f6 AS cedar
RUN cargo install cedar-policy-cli --version 4.11.0 --locked

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
COPY --from=cedar /usr/local/cargo/bin/cedar /usr/local/bin/cedar
WORKDIR /app
COPY gateway/gateway.py ./gateway.py
COPY policies.cedar entities.json ./
# Run unprivileged (the cedar binary in /usr/local/bin is world-executable).
RUN useradd -m -u 1000 gateway && chown -R gateway:gateway /app
USER gateway
EXPOSE 8080
ENTRYPOINT ["python", "gateway.py", "--port", "8080", \
            "--policies", "policies.cedar", "--entities", "entities.json"]
