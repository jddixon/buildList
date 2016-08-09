#!/usr/bin/python3

# buildList/setup.py

import re
from distutils.core import setup
__version__ = re.search("__version__\s*=\s*'(.*)'",
                        open('buildList/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='buildList',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['buildList'],
      # following could be in scripts/ subdir
      scripts=['blBootstrap', 'blCheck', 'blListGen', 'blSrcGen', ],
      # MISSING description
      classifiers=[
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
      ],
      )
