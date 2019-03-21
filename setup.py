from setuptools import setup

setup(
    name='auditmonitor',
    version='1.0',
    packages=['auditmonitor'],
    url='https://github.com/alslater/auditmonitor',
    license='',
    author='Al Slater',
    author_email='al.slater@essiell.com',
    description='BSM audit monitor',
    scripts=[
        'bin/auditmon'
    ],
    install_requires=['watchdog']
)
