FROM registry.fedoraproject.org/fedora:latest

RUN set -x \
    && dnf -y install /usr/bin/flit python3-orderedset python3-openstacksdk python3-yaml

COPY . /sgmanager
WORKDIR /sgmanager

RUN set -x \
    && FLIT_ROOT_INSTALL=1 FLIT_NO_NETWORK=1 flit install -s

VOLUME ["/run/sgmanager"]
WORKDIR /run/sgmanager
ENTRYPOINT ["/usr/bin/sgmanager"]
