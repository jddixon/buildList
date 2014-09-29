#!/usr/bin/python

# buildList/setup.py

import re
from distutils.core import setup
__version__ = re.search("__version__\s*=\s*'(.*)'",
                    open('buildList/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup ( name         = 'buildList', 
        version      = __version__,
        author       = 'Jim Dixon',
        author_email = 'jddixon@gmail.com',
        py_modules   = [ ],
        packages     = ['buildList'], 
        # following could be in scripts/ subdir
        scripts      = [ ],          # front end module(s)
        # MISSING url
        )
