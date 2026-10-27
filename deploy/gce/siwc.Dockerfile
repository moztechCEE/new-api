# Pinned official Node 22 linux/amd64 runtime; no npm dependencies or secrets.
FROM node:22-bookworm-slim@sha256:ea11b74b986d520137cdef9a5346e447a00f275ecc4abc0055b7151226231e09
WORKDIR /opt/new-api-siwc-dev
COPY --chown=1000:1000 bin/siwc-local-runtime.mjs bin/siwc-local-sessions.mjs bin/siwc-local-vm.mjs ./
COPY --chown=1000:1000 bin/siwc-local-model-port.mjs bin/corely-model-contract.mjs ./
COPY --chown=1000:1000 bin/siwc-gateway-model-port.mjs ./
COPY --chown=1000:1000 bin/siwc-local-corely-worker.mjs bin/corely-vm-model-job-client.mjs bin/corely-vm-model-worker.mjs ./
COPY --chown=1000:1000 LICENSE THIRD-PARTY-LICENSES.md ./
USER 1000:1000
ENTRYPOINT ["node", "/opt/new-api-siwc-dev/siwc-local-vm.mjs"]
CMD ["maintain", "--state-dir", "/state"]
