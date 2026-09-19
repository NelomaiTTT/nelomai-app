FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-pyatspi python3-cryptography dbus-x11 xvfb xauth libwebkit2gtk-4.1-0 \
    libayatana-appindicator3-1 librsvg2-2 libssl3t64 ca-certificates fonts-dejavu-core \
    procps util-linux libglib2.0-bin gsettings-desktop-schemas \
    && useradd --create-home acceptance
COPY --chown=0:0 scripts /opt/nelomai-acceptance/scripts
COPY --chown=0:0 scripts/linux/check-runtime-webview.py /opt/nelomai-acceptance/check-runtime-webview.py
COPY --chown=0:0 verify-runtime-manifest /opt/nelomai-acceptance/verify-runtime-manifest
COPY --chown=0:0 linux-runtime-acceptance /opt/nelomai-acceptance/linux-runtime-acceptance
COPY --chown=0:0 inputs /opt/nelomai-acceptance/inputs
ENV NELOMAI_RUNTIME_CONTRACT_VERIFIER=/opt/nelomai-acceptance/verify-runtime-manifest
ENTRYPOINT ["python3", "/opt/nelomai-acceptance/scripts/linux/run-package-acceptance.py", "--inside"]
