# sgmanager

Tooling for management of security groups.
Load local configuration, load remote groups and apply differences.

## Installation
With PIP:

	pip install -e 'git://github.com/gooddata/sgmanager.git#egg=sgmanager'

Or from local GIT checkout:

	python setup.py install

Or you can run execution script from checkouted root directory without installation:

	./bin/sgmanager.py

## Usage
First setup *EC2\_ACCESS\_KEY* and *EC2\_SECRET\_KEY* environment variables. You can also set *EC2\_URL* to connect to custom EC2 endpoint (eg. OpenStack).
Alternatively set these options from command line.

Setup is submitted by simple YAML configuration, it can be dumped from current EC2 account by running:

	./bin/sgmanager.py --dump > conf/aws-dev.yaml

Then you can edit output yaml file and run following to see the diff:

	./bin/sgmanager.py -c conf/aws-dev.yaml

To apply it, force run with parameter *-f* / *--force*.

To avoid removal of existing groups that aren't present in config file, use parameter *--no-remove*
