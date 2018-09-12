FROM harbor.intgdc.com/tools/gdc-python-tox

COPY . /sgmanager
WORKDIR /sgmanager

RUN set -x \
    && python3.6 -m pip install flit \
    && FLIT_ROOT_INSTALL=1 flit install -s

VOLUME ["/run/sgmanager"]
WORKDIR /run/sgmanager
ENTRYPOINT ["/usr/bin/sgmanager"]
