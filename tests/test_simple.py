import pathlib

import pytest

from sgmanager.manager import SGManager
from sgmanager.utils import dump_groups

EXAMPLES_DIR = pathlib.Path(__file__).parent / 'examples'


@pytest.mark.parametrize('config, config_expanded', (
    ('groups.yaml', 'groups.expanded.yaml'),
    ('groups.deprecated.yaml', 'groups.deprecated.expanded.yaml'),
))
def test_parse(config, config_expanded):
    manager = SGManager()
    manager.load_local_groups(EXAMPLES_DIR / config)
    with open(EXAMPLES_DIR / config_expanded, 'r') as fp:
        expected = fp.read()
    assert dump_groups(manager.local, default_flow_style=False, width=-1) == expected
