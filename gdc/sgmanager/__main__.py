# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import logging
import sys
from gdc.sgmanager.cli import main

try:
    main()
except (KeyboardInterrupt, SystemExit):
    # User interruption
    sys.exit(1)
except Exception as e:
    if getattr(e, 'friendly', False):
        # Friendly exceptions - just log and exit
        lg = logging.getLogger('gdc.sgmanager')
        lg.error(e)
        sys.exit(1)
    else:
        # Evil exceptions, print stack trace
        raise