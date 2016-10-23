#!/usr/bin/python3
# buildlist/setup.py

""" Set up disutils for buildlist. """

import re
from distutils.core import setup
__version__ = re.search(r"__version__\s*=\s*'(.*)'",
                        open('buildlist/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='buildlist',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['buildlist'],
      # following could be in scripts/ subdir
      scripts=['bl_bootstrap', 'bl_check', 'bl_create_test_data1',
               'bl_list_gen', 'bl_src_gen', ],
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
