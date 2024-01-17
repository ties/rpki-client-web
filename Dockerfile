FROM fedora:39

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y tini \
  && dnf install -y rpki-client \
    --enablerepo=updates-testing \
    --best \
  && yum info rpki-client >> /rpki-client-version.txt \
  && dnf clean all \
  && rm -rf /var/cache/yum

#
# Tini is used from the base image distribution since this is cross-architecture.
#

ADD . /opt/rpkiclientweb
# Alternative to poetry install: `poetry export` to create requirements.txt.
RUN cd /opt/rpkiclientweb \
  && dnf --setopt=install_weak_deps=False --best install -y python3-devel git gcc python3-devel python3-pip \
  && python3 -m pip install poetry \
  && python3 -m poetry config virtualenvs.create false \
  && python3 -m poetry install --without dev \
  && dnf remove -y git gcc python3-devel \
  && mkdir /opt/rpkiclientweb/cache /opt/rpkiclientweb/output /config\
  && chown -R daemon:daemon /opt/rpkiclientweb /config/
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]


ADD config.yml /config/


# default port from default config
EXPOSE 8888

ENTRYPOINT ["tini", "--"]

USER daemon
# Run your program under Tini
CMD ["python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
