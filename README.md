# sgmanager

Tooling for management of security groups.
Load local configuration, load remote groups and apply differences.

## Installation
With PIP from Github:

	pip install -e 'git://github.com/gooddata/sgmanager.git#egg=sgmanager'

Or with PIP from Pypi:

	pip install sgmanager

Or from local GIT checkout:

	python setup.py install

Then you can run it by *sgmanager* command, ensure that you have python bin in your $PATH, eg:
/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin

Or you can run execution script from checkouted root directory without installation:

	python gdc/sgmanager

## Usage
	usage: sgmanager [-h] [-c CONFIG] [--dump] [--unused] [--remove-unused] [-f]
	                 [-q] [-d] [--no-remove] [--no-remove-groups]
	                 [-I EC2_ACCESS_KEY] [-S EC2_SECRET_KEY] [-R EC2_REGION]
	                 [-U EC2_URL] [-t TIMEOUT] [-m MODE] [--insecure]
	                 [--cert CERT]

	Security groups management tool

	optional arguments:
	  -h, --help            show this help message and exit
	  -c CONFIG, --config CONFIG
	                        Config file to use
	  --dump                Dump remote groups and exit
	  --unused              Dump groups not used by any instance
	  --remove-unused       Only remove groups that are not used by any instance
	  -f, --force           Force action (otherwise run dry-run)
	  -q, --quiet           Be quiet, print only WARN/ERROR output
	  -d, --debug           Debug mode
	  --no-remove           Do not remove any groups or rules, only add
	  --no-remove-groups    Do not remove any groups, only add
	  -I EC2_ACCESS_KEY, --ec2-access-key EC2_ACCESS_KEY
	                        EC2 Access Key to use
	  -S EC2_SECRET_KEY, --ec2-secret-key EC2_SECRET_KEY
	                        EC2 Secret Key to use
	  -R EC2_REGION, --ec2-region EC2_REGION
	                        Region to use (default us-east-1)
	  -U EC2_URL, --ec2-url EC2_URL
	                        EC2 API URL to use (otherwise use default)
	  -t TIMEOUT, --timeout TIMEOUT
	                        Set socket timeout (default 120s)
	  -m MODE, --mode MODE  Mode for validating group name and description
	                        (default a)
	  --insecure            Do not validate SSL certs
	  --cert CERT           Path to CA certificates (eg. /etc/pki/cacert.pem)

First setup *EC2\_ACCESS\_KEY* and *EC2\_SECRET\_KEY* environment variables. You can also set *EC2\_URL* to connect to custom EC2 endpoint (eg. OpenStack).
Alternatively set these options from command line.

Setup is submitted by simple YAML configuration, it can be dumped from current EC2 account by running:

	./bin/sgmanager.py --dump > conf/aws-dev.yaml

Then you can edit output yaml file and run following to see the diff:

	./bin/sgmanager.py -c conf/aws-dev.yaml

To apply it, force run with parameter *-f* / *--force*.

To avoid removal of existing groups that aren't present in config file, use parameter *--no-remove*

Each configured group passes validation, group name and description shoul not exceed 255 characters.

There are several modes for string validation of both group name and description, set by *-m* / *--mode*:
- a, ascii - only ASCII characters
- s, strict - matches [a-zA-Z0-9_- ]
- v, vpc - string can contain only a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*

Mode depends on cloud used, for AWS EC2 *-a* is recommended, for AWS EC2 VPC *-v* and for OpenStack with *ec2_strict_validation=on* *-s*

## Configuration options
	---
	test1:
	  description: "SGManager testing security group"
	  rules:
		- port: 22
		  # tcp, udp or icmp
		  protocol: tcp
		  # IP ranges that are allowed to connect, can be list or string
		  cidr: [108.171.171.226/32]

		- port: 80
		  protocol: tcp
		  groups:
			# You can define security group from other account
			- {name: test2, owner: xyz2137}
	test2:
	  description: "SGManager testing security group number 2"
	  rules:
		- port_from: 50000
		  port_to: 50500
		  groups:
			- test1

## TODO
- support for VPC groups
