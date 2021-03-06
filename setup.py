#!/usr/bin/python3
# buildlist/setup.py

""" Setuptools project configuration for buildlist. """

from os.path import exists
from setuptools import setup

long_desc = None
if exists('README.md'):
    with open('README.md', 'r') as file:
        long_desc = file.read()

setup(name='buildlist',
      version='0.10.9',
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      long_description=long_desc,
      packages=['buildlist'],
      package_dir={'': 'src'},
      py_modules=[],
      include_package_data=False,
      zip_safe=False,
      scripts=['src/fix_builds', 'src/bl_check', 'src/bl_createtestdata1',
               'src/bl_listgen', 'src/bl_srcgen'],
      ext_modules=[],
      description='digitally signed indented list of content keys',
      url='https://jddixon.github.io/buildlist',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python',
          'Programming Language :: Python 2',
          'Programming Language :: Python 2.7',
          'Programming Language :: Python 3',
          'Programming Language :: Python 3.5',
          'Programming Language :: Python 3.6',
          'Programming Language :: Python 3.7',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],)
