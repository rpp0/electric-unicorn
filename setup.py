#!/usr/bin/env python

import numpy as np
from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize

ext = Extension('celectricunicorn',
        sources = ['simulate.c', 'celectricunicorn.pyx'],
        #library_dirs = [CUDA['lib64']],
        libraries = ['unicorn'],
        language = 'c',
        #runtime_library_dirs = [CUDA['lib64']],

        #extra_compile_args= {
        #    'gcc': ['-O3', '-fopenmp', '-ffast-math'],
        #    'nvcc': [
        #        '-O3', '--use_fast_math', '-Xcompiler', '-fopenmp -ffast-math -O3',
        #        '-arch=sm_52', '--ptxas-options=-v', '-c',
        #        '--compiler-options', "'-fPIC'"
        #        ]
        #},
		#extra_link_args = ['-fopenmp'],
        include_dirs = [np.get_include()]
    )

setup(
    name='Electric Unicorn',
    ext_modules=cythonize([ext]),
    version='',
    packages=[''],
    url='',
    license='',
    author='Pieter Robyns',
    author_email='',
    description='',
    zip_safe=False
)
