__author__ = 'ling'

from distutils.core import setup
from setuptools import find_packages

setup(
      name="ELFfile",
      version="0.1",
      description="a ELF file parse tool",
      author="Ling",
      author_email='ling_pro@163.com',
      url="http://www.github.com/MatrixLing/Elffile",
      packages=['.'], install_requires=['zio',"vivisect-vstruct-wb>=1.0.1b1"]
)
