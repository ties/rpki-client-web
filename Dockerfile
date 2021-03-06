FROM fedora:33

WORKDIR /opt/rpkiclientweb

# Use dependencies from fedora as much as possible, saves building them and build deps.
RUN dnf --setopt=install_weak_deps=False --best install -y rpki-client python3-aiohttp python3-pyyaml python3-pip git\
	&& dnf clean all \
  	&& rm -rf /var/cache/yum

# S6 init-like system for proper <C-c>
ADD https://github.com/just-containers/s6-overlay/releases/download/v2.0.0.1/s6-overlay-amd64.tar.gz /tmp/
RUN tar xzf /tmp/s6-overlay-amd64.tar.gz -C / --exclude='./bin' && tar xzf /tmp/s6-overlay-amd64.tar.gz -C /usr ./bin && rm /tmp/s6-overlay-amd64.tar.gz

ADD . /opt/rpkiclientweb
VOLUME ["/opt/rpkiclientweb/cache", "/opt/rpkiclientweb/output", "/config"]

RUN cd /opt/rpkiclientweb\
	&& pip install -r requirements.txt

# https://github.com/just-containers/s6-overlay functionality
ADD docker/rpkiclientweb.init /etc/cont-init.d/02-rpkiclientweb
ADD docker/rpkiclientweb.chmod /etc/fix-attrs.d/01-rpki-client-web
ADD config.yml /config/


# default port from default config
EXPOSE 8888

ENTRYPOINT ["/init"]
CMD ["s6-setuidgid", "daemon", "python3", "-m", "rpkiclientweb", "-c", "/config/config.yml", "-v"]
