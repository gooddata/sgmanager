from gdc.sgmanager import SGManager
manager = SGManager('./conf/groups.yaml')
manager.load_remote_groups()
