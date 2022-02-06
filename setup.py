from setuptools import setup

setup(
    name = 'distill',
    version = '0.1.0',
    packages = ['distill'],
    entry_points = {
        'console_scripts': [
            'distill = distill.__main__:entry'
        ]
    })