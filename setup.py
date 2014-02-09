from setuptools import setup
import mysqlproxy

LONG_DESC = """
mysqlproxy is a proxy for a MySQL server.  It uses a hook
system to allow interception of any part of the MySQL protocol.
"""

VERSION = mysqlproxy.__version__

setup(
    name='mysqlproxy',
    version=VERSION,
    packages=['mysqlproxy'],
    scripts=['bin/mysqlproxy-standalone'],
    description='proxy library for MySQL',
    author='Pat Mac',
    author_email='itgpmc@gmail.com',
    long_description=LONG_DESC,
    license='MIT',
    url='https://github.com/spigwitmer/mysqlproxy',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Topic :: Database'
        ]
    )
