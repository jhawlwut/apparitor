# Two stages: take the official OPA binary, then run the stdlib gateway alongside it.
# Both stages are offline — the OPA image is pinned by digest, so nothing is fetched at
# build or run time. Build context is examples/opa/ so the vendored policy + data are copied.

# openpolicyagent/opa:1.17.1-static — static binary at /opa, pinned by digest.
FROM openpolicyagent/opa:1.17.1-static@sha256:c29f8ee8dbe66608a1c04e9be84b04efc46877625e6b0877e559954565209efc AS opa

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
COPY --from=opa /opa /usr/local/bin/opa
WORKDIR /app
COPY gateway/gateway.py ./gateway.py
COPY policy.rego data.json ./
# Run unprivileged (the opa binary in /usr/local/bin is world-executable).
RUN useradd -m -u 1000 gateway && chown -R gateway:gateway /app
USER gateway
EXPOSE 8080
ENTRYPOINT ["python", "gateway.py", "--port", "8080", \
            "--policy", "policy.rego", "--data", "data.json"]
