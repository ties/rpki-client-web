FROM fedora:37

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y python3-aiohttp python3-pyyaml python3-pip python3-wrapt git\
  && dnf install -y rpki-client --enablerepo=updates-testing,updates-testing-modular --best \
  && dnf clean all \
  && rm -rf /var/cache/yum

# Add Tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

ADD . /opt/rpkiclientweb
RUN mkdir /opt/rpkiclientweb/cache /opt/rpkiclientweb/output /config\
  && chown -R daemon:daemon /opt/rpkiclientweb /config/
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]

RUN cd /opt/rpkiclientweb\
	&& pip install -r requirements.txt

ADD config.yml /config/


# default port from default config
EXPOSE 8888

ENTRYPOINT ["/tini", "--"]

USER daemon
# Run your program under Tini
CMD ["python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
