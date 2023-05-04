FROM fedora:38

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y python3-aiohttp python3-pyyaml python3-poetry python3-wrapt git tini \
  && dnf install -y rpki-client \
    --enablerepo=updates-testing,updates-testing-modular \
    --best \
    --advisory=FEDORA-2023-c1bd199900 \
  && dnf clean all \
  && rm -rf /var/cache/yum
# --advisory=FEDORA-2023-c1bd199900: rpki-client 8.4.1 on 4-5-2023

#
# Tini is used from the base image distribution since this is cross-architecture.
#

ADD . /opt/rpkiclientweb
# Alternative to poetry install: `poetry export` to create requirements.txt.
RUN cd /opt/rpkiclientweb \
  && python3 -m poetry config virtualenvs.create false \
  && python3 -m poetry install --without dev
RUN mkdir /opt/rpkiclientweb/cache /opt/rpkiclientweb/output /config\
  && chown -R daemon:daemon /opt/rpkiclientweb /config/
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]


ADD config.yml /config/


# default port from default config
EXPOSE 8888

ENTRYPOINT ["tini", "--"]

USER daemon
# Run your program under Tini
CMD ["python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
