#!/usr/bin/python3
# buildlist/setup.py

""" Set up disutils for buildlist. """

import re
from distutils.core import setup
__version__ = re.search(r"__version__\s*=\s*'(.*)'",
                        open('src/buildlist/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='buildlist',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['src/buildlist'],
      # following could be in scripts/ subdir
      scripts=['src/bl_bootstrap', 'src/bl_check', 'src/bl_createtestdata1',
               'src/bl_listgen', 'src/bl_srcgen', ],
      description='digitally signed indented list of content keys',
      url='https://jddixon.github.com/buildlist',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],)
