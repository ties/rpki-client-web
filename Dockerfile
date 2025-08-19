FROM fedora:42 as builder

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y tini rpki-client python3-uv \
  && dnf install -y rsync --best \
  && dnf install -y @development-tools python3-devel \
  && yum info rpki-client >> /rpki-client-version.txt \
  && dnf clean all \
  && rm -rf /var/cache/yum

#
# Tini is used from the base image distribution since this is cross-architecture.
#

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Disable Python downloads, because we want to use the system interpreter
# across both images. If using a managed Python version, it needs to be
# copied from the build image into the final image; see `standalone.Dockerfile`
# for an example.
ENV UV_PYTHON_DOWNLOADS=0

WORKDIR /opt/rpkiclientweb
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev
COPY . /opt/rpkiclientweb
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

FROM fedora:42

RUN dnf --setopt=install_weak_deps=False --best install -y tini rpki-client \
  && yum info rpki-client >> /rpki-client-version.txt \
  && dnf clean all \
  && rm -rf /var/cache/yum

COPY --from=builder --chown=daemon:daemon /opt/rpkiclientweb /opt/rpkiclientweb
RUN cd /opt/rpkiclientweb \
  && mkdir /opt/rpkiclientweb/cache /opt/rpkiclientweb/output /config \
  && chown -R daemon:daemon /opt/rpkiclientweb /config/ \
  && dnf install -y python3
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]

ADD config.yml /config/

USER daemon
WORKDIR /opt/rpkiclientweb

# default port from default config
EXPOSE 8888

ENTRYPOINT ["tini", "--"]

# Run your program under Tini
CMD ["./.venv/bin/python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
