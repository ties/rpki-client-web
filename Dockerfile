FROM fedora:42 AS builder

# configure dnf to pick best and no weak dependencies
RUN echo -e '[main]\ninstall_weak_deps=False\nbest=True' > /etc/dnf/dnf.conf

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN --mount=type=cache,sharing=locked,target=/var/cache/dnf \
    --mount=type=cache,sharing=locked,target=/var/cache/libdnf5 \
  dnf install -y tini rpki-client python3-uv rsync \
  && dnf install -y @development-tools python3-devel \
  && yum info rpki-client >> /rpki-client-version.txt

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
RUN --mount=type=cache,sharing=locked,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev
COPY . /opt/rpkiclientweb
RUN --mount=type=cache,sharing=locked,target=/root/.cache/uv \
    uv sync --locked --no-dev

FROM fedora:42

# configure dnf to pick best and no weak dependencies
RUN echo -e '[main]\ninstall_weak_deps=False\nbest=True' > /etc/dnf/dnf.conf

RUN --mount=type=cache,sharing=locked,target=/var/cache/dnf \
    --mount=type=cache,sharing=locked,target=/var/cache/libdnf5 \
  dnf install -y tini rpki-client rsync \
  && yum info rpki-client >> /rpki-client-version.txt

COPY --from=builder --chown=daemon:daemon /opt/rpkiclientweb /opt/rpkiclientweb
WORKDIR /opt/rpkiclientweb
RUN --mount=type=cache,sharing=locked,target=/var/cache/dnf \
    --mount=type=cache,sharing=locked,target=/var/cache/libdnf5 \
  mkdir /opt/rpkiclientweb/cache /opt/rpkiclientweb/output /config \
  && chown -R daemon:daemon /opt/rpkiclientweb /config/ \
  && dnf install -y python3

# Make sure the venv is on the path
ENV PATH="/opt/rpkiclientweb/.venv/bin:$PATH"
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]

ADD config.yml /config/

USER daemon

# default port from default config
EXPOSE 8888

ENTRYPOINT ["tini", "--"]

# Run your program under Tini
CMD ["./.venv/bin/python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
