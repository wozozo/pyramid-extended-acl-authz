import os
import sys
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['pyramid']

setup(
    name='pyramid-extended-acl-authz',
    version='0.0.0',
    description='pyramid-extended-acl-authz',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "License :: OSI Approved :: MIT License",
        ],
    author='Moriyoshi Koizumi',
    author_email='mozo@mozo.jp',
    url='https://github.com/moriyoshi/pyramid-extended-acl-authz',
    keywords='web pyramid authorization',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    setup_requires=[
        'pytest-runner',
        ],
    install_requires=[
        'pyramid',
        ],
    tests_require=[
        'pytest',
        'webtest',
        'mock',
        ],
    test_suite="pyramid_extended_acl_authz"
    )
