#!/usr/bin/python
# -*- coding: UTF-8 -*-
#

# Install model files
from setuptools import setup,find_packages
setup(name='ppool',
      version='0.0.1',
      description='process pool lib!',
      author='wenhai.zhou',
      author_email='shockerjue@gmail.com',
      requires=[], # Define which modules you depend on
      packages=find_packages(), # The system automatically starts looking for packages from the current directory
      # If some packages do not need to be packaged, you can only specify the files that need to be packaged
      license='apache 3.0')
