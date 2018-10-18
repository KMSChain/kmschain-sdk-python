#
import os
import shutil

#
from distutils.core import setup, Extension
from distutils.command.build_py import build_py
from distutils.command.clean import clean
from subprocess import check_output

#
proxylib_module = Extension('', sources = ['kmschain/proxylib.cpp'], extra_compile_args=["-fPIC", "-std=c++11"], language="c++", extra_link_args=['kmschain/libProxyLib.a',"kmschain/libmbedcrypto.a", "kmschain/libmbedtls.a", "kmschain/libmbedx509.a"])

#
class BuilderClass(build_py):
    LIBNAME="ProxyLib"
    LIBFILE="lib" + LIBNAME + ".a"
    SOURCE_DIR=os.getcwd()
   

    def run(self):
      os.system("git clone https://github.com/kmschain/kmschain-sdk-cpp {}".format(self.LIBNAME))
      os.chdir("{}/{}".format(self.SOURCE_DIR, self.LIBNAME))
      if os.path.exists("build"):
          shutil.rmtree("build", ignore_errors=True)
      os.mkdir("build")
      os.chdir("build")
             
      os.system("cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE='ON'")
      os.system("make -j4")
      os.system("cp {} {}/kmschain".format(self.LIBFILE, self.SOURCE_DIR))
      os.chdir("{}".format(self.SOURCE_DIR))
      shutil.rmtree("{}".format(self.LIBNAME))

#
class CleanClass(clean):
    SOURCE_DIR=os.getcwd()
    
    def run(self):
        os.system("cp build/lib.linux-x86_64-3.5/.cpython-35m-x86_64-linux-gnu.so {}/kmschain/proxylib.so".format(self.SOURCE_DIR))
        os.system("cp build/lib.linux-x86_64-3.5/.cpython-35m-x86_64-linux-gnu.so {}/tests/proxylib.so".format(self.SOURCE_DIR))
        shutil.rmtree("{}".format("build"))

#
setup(name='kmschain',
      version='0.1.0',
      python_requires='>3', 
      description='Python sdk for KMSChain API functionality.',
      ext_modules=[proxylib_module],
      packages=['kmschain', 'tests'],
      cmdclass={'build_py': BuilderClass, 'clean': CleanClass}
      )
