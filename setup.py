from setuptools import find_packages
from setuptools import setup

__version__ = '0.69.0'

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='cartography',
    version=__version__,
    description='Explore assets and their relationships across your technical infrastructure.',
    long_description='file: README.md',
    long_description_content_type='text/markdown',
    url='https://www.github.com/lyft/cartography',
    maintainer='Lyft',
    maintainer_email='security@lyft.com',
    license='apache2',
    packages=find_packages(exclude=['tests*']),
    package_data={
        'cartography': ['py.typed'],
        'cartography.data': [
            '*.cypher',
            '*.yaml',
        ],
        'cartography.data.jobs.analysis': [
            '*.json',
        ],
        'cartography.data.jobs.cleanup': [
            '*.json',
        ],
    },
    dependency_links=[],
    install_requires=requirements,
    extras_require={
        ':python_version<"3.7"': [
            "importlib-resources",
        ],
    },
    entry_points={
        'console_scripts': [
            'cartography = cartography.cli:main',
            'cartography-detectdrift = cartography.driftdetect.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
