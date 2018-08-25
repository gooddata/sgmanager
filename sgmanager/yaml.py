# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2018, GoodData Corporation. All rights reserved.

import functools
import pathlib

import yaml
from yaml import SafeLoader, SafeDumper
from yaml.representer import SafeRepresenter


class LocalRepresenter(SafeRepresenter):
    '''Safe YAML representer with functions to support few custom types.'''
    def represent_to_str(self, value):
        return self.represent_str(str(value))

    def represent_str_enum(self, enum_value):
        return self.represent_str(enum_value.value)

    def represent_base_class(self, base):
        return self.represent_dict(base.to_dict(True))

    def represent_ordered_dict(self, ordered_dict):
        return self.represent_dict(ordered_dict.items())


class LocalLoader(SafeLoader):
    '''Safe YAML loader which supports search_path.'''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if hasattr(self.stream, 'name'):
            path = pathlib.Path(self.stream.name).parent
        else:
            path = pathlib.Path.cwd()
        self.search_path = path.resolve()


class LocalDumper(LocalRepresenter, SafeDumper):
    '''Safe YAML dumper which supports few custom types.'''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        from .utils import Base, StrEnum
        self.add_multi_representer(Base,
                                   type(self).represent_base_class)
        self.add_multi_representer(StrEnum,
                                   type(self).represent_str_enum)
        from ipaddress import IPv4Network, IPv6Network
        self.add_representer(IPv4Network,
                             type(self).represent_to_str)
        self.add_representer(IPv6Network,
                             type(self).represent_to_str)
        from collections import OrderedDict
        self.add_representer(OrderedDict,
                             type(self).represent_ordered_dict)


class BaseYAMLObject(yaml.YAMLObject):
    yaml_loader = LocalLoader
    yaml_dumper = LocalDumper


class YamlInclude(BaseYAMLObject):
    '''YAML object which expands to included file.'''
    yaml_tag = '!include:'

    @classmethod
    def _from_file(cls, loader, node):
        fpath = loader.search_path / loader.construct_yaml_str(node)
        with open(fpath, 'r') as fp:
            return yaml.load(fp, type(loader))

    @classmethod
    def from_yaml(cls, loader, node):
        if isinstance(node, yaml.ScalarNode):
            return cls._from_file(loader, node)
        elif isinstance(node, yaml.SequenceNode):
            return '\n'.join(cls._from_file(loader, scalar_node)
                             for scalar_node in node.value)
        else:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f'expected either a sequence or scalar node, {node.id} found',
                node.start_mark)


def load(stream, **kwargs):
    '''Load YAML from stream using local loader.'''
    return yaml.load(stream, functools.partial(LocalLoader, **kwargs))


def dump(data, stream=None, **kwargs):
    '''Dump YAML to stream using local dumper.'''
    return yaml.dump(data, stream, Dumper=LocalDumper, **kwargs)
