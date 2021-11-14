FROM fedora:35

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y rpki-client python3-aiohttp python3-pyyaml python3-pip python3-wrapt git\
	&& echo "Temporarily enabling the Fedora security advisory for rpki-client 7.5" \
  && dnf update -y --enablerepo=updates-testing --advisory=FEDORA-2021-c9852f0be4 \
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
