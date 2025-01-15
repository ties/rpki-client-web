FROM fedora:41

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
# FEDORA-2025-ec87287710: rsync CVEs in 1-2025.
RUN dnf --setopt=install_weak_deps=False --best install -y tini rpki-client \
  && dnf install -y rsync \
    --enablerepo=updates-testing \
    --advisory=FEDORA-2025-ec87287710 && echo "2025-01-15: rsync 3.4.0-1.fc41" \
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
  && dnf --setopt=install_weak_deps=False --best install -y python3-devel python3-pip git-core gcc python3-devel \
  && python3 -m pip install poetry \
  && python3 -m poetry config virtualenvs.create false \
  && python3 -m poetry install --without dev \
  && dnf remove -y git-core gcc python3-devel \
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
