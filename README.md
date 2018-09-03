# sgmanager

OpenStack Security Groups Management Tool.

## Configuration

See [groups.yaml](examples/groups.yaml) for specification
and its [expanded version](examples/groups.expanded.yaml).

## Installation & Running

Running from source tree can be done in 2 ways:

* Using [flit](https://flit.readthedocs.io): `flit install -s` and then use `sgmanager` from `$PATH`
* Using Python directly: `python3 -m sgmanager`

Installation can be done using `flit install`. See `--help` from it.

## Running tests

`py.test-3 -vv`

## Supplying credentials

There are [3 standard ways](https://docs.openstack.org/openstacksdk/latest/user/config/configuration.html)
of passing credentials for OpenStack environments:

* `--os-*` option for commandline
* `export OS_*` from environment variables
* `clouds.yaml` and use `--os-cloud` option

## Notes

- Egress rules have not been tested
