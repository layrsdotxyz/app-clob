FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY layrs-direct-enclave /opt/layrs-opening/layrs-direct-enclave
COPY OPENING_EPOCH_STATE_20260911.json /opt/layrs-opening/OPENING_EPOCH_STATE_20260911.json
COPY OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json /opt/layrs-opening/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json
ENV LAYRS_OPENING_EPOCH_PATH=/opt/layrs-opening/OPENING_EPOCH_STATE_20260911.json
ENV LAYRS_OPENING_EVIDENCE_PATH=/opt/layrs-opening/OPENING_EPOCH_EVIDENCE_MANIFEST_20260911.json
ENTRYPOINT ["/opt/layrs-opening/layrs-direct-enclave"]
