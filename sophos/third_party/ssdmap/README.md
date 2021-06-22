# ssdmap

`ssdmap` provides an implementation of a disk resident map data structure designed to have good performances on SSDs.
I uses memory maps, and hence uses all the available RAM as a sort of cache.

## Building

Building is done through [SConstruct](http://www.scons.org). 
Three targets can be built:

* `debug`: the executable constructed from the `main.cpp` file. It must be used as a debugging tool (to develop new features), and for benchmarking. It is the default target.

* `check`: unit tests.

* `lib`: the compiled library. It produces both the static and the shared versions of `libssdmap`, copied in the directory `library/lib`, together with the headers in `library/include`. If possible, unit tests are run before constructing the library.

* `doc`: the documentation. Generates the documentation using doxygen (you need doxygen installed on the host).

To build the library, just enter in your terminal
``scons lib ``.

You can also use the Xcode project if you are running on Mac OS X.

### Compiler

`ssdmap` needs a compiler supporting C++11. It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3 and on Mac OS X.10 using clang 7.0.0


## Contributors

Unless otherwise stated, the code has been written by [Raphael Bost](http://people.irisa.fr/Raphael.Bost/).

## Licensing

The code is licensed under the [GNU General Public License v3](http://www.gnu.org/licenses/gpl.html).

![GPL](http://www.gnu.org/graphics/gplv3-88x31.png)

