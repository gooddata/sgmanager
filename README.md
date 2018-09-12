# sgmanager

OpenStack Security Groups Management Tool.

## Configuration

See [groups.yaml](examples/groups.yaml) for specification
and its [expanded version](examples/groups.expanded.yaml).

Sample configuration:

```yaml
document: sgmanager-groups
version: 1
data:
  - test1:
      description: SGManager testing security group
      rules:
      - cidr: [108.171.171.226/32]
        port: 22
        protocol: tcp
      - groups: [test2]
        port: 80
        protocol: tcp
  - test2:
      description: SGManager testing security group number 2
      rules:
      - groups: [test1]
        port_min: 50000
        port_max: 50500
        protocol: tcp
```

Sample configuration using old format:

```yaml
test1:
  description: SGManager testing security group
  rules:
  - cidr: [108.171.171.226/32]
    port: 22
    protocol: tcp
  - groups: [test2]
    port: 80
    protocol: tcp
test2:
  description: SGManager testing security group number 2
  rules:
  - groups: [test1]
    port_from: 50000
    port_to: 50500
    protocol: tcp
```

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
