# -*- coding: utf-8 -*-

import alipay
from distutils.core import setup


setup(
    name = "alipay",
    version = alipay.__version__,
    packages=['alipay'],
    package_dir={'alipay': 'alipay'},
    package_data={'alipay': ['config/*.yaml']},
    include_package_data = True,
    author = "finalbattle",
    author_email = "finalbattle@gmail.com",
    url = "https://github.com/finalbattle/alipay",
    description = "alipay util package",
    install_requires=[],
)
