![img](https://openzfs.github.io/openzfs-docs/_static/img/logo/480px-Open-ZFS-Secondary-Logo-Colour-halfsize.png)

OpenZFS is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community.
This repository contains the code for running OpenZFS on Linux and FreeBSD.

[![codecov](https://codecov.io/gh/openzfs/zfs/branch/master/graph/badge.svg)](https://codecov.io/gh/openzfs/zfs)
[![coverity](https://scan.coverity.com/projects/1973/badge.svg)](https://scan.coverity.com/projects/openzfs-zfs)

# Official Resources

  * [Documentation](https://openzfs.github.io/openzfs-docs/) - for using and developing this repo
  * [ZoL site](https://zfsonlinux.org) - Linux release info & links
  * [Mailing lists](https://openzfs.github.io/openzfs-docs/Project%20and%20Community/Mailing%20Lists.html)
  * [OpenZFS site](https://openzfs.org/) - for conference videos and info on other platforms (illumos, OSX, Windows, etc)

# Installation

Full documentation for installing OpenZFS on your favorite operating system can
be found at the [Getting Started Page](https://openzfs.github.io/openzfs-docs/Getting%20Started/index.html).

# Contribute & Develop

We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).

We have a [Code of Conduct](./CODE_OF_CONDUCT.md).

# Release

OpenZFS is released under a CDDL license.
For more details see the NOTICE, LICENSE and COPYRIGHT files; `UCRL-CODE-235197`

# Supported Kernels
  * The `META` file contains the officially recognized supported Linux kernel versions.
  * Supported FreeBSD versions are any supported branches and releases starting from 13.0-RELEASE.

# MacOS Tahoe 26.4 compiling steps
```sh
# 1) install build tools
brew install autoconf automake libtool pkg-config openssl gettext coreutils
# 2)
git checkout zfs-macOS-2.4.1-release
# 3)
sh autogen.sh
# 4)
./configure \                         
  CPPFLAGS="-I/opt/homebrew/opt/gettext/include -I/opt/homebrew/opt/openssl@3/include" \
  LDFLAGS="-L/opt/homebrew/opt/gettext/lib -L/opt/homebrew/opt/openssl@3/lib"
# 5)
make -s -j$(sysctl -n hw.ncpu)
```
There should be compiling error:
```sh
module/os/macos/spl/spl-kmem.c:5662:32: error: incompatible function pointer types passing 'void (void)' to parameter of type 'thread_func_t'
      (aka 'void (*)(void *)') [-Wincompatible-function-pointer-types]
 5662 |         (void) thread_create(NULL, 0, spl_free_thread, 0, 0, 0, 0, 92);
```
just modify module/os/macos/spl/spl-kmem.c:4650 to "spl_free_thread(void *arg __unused)", and continue.
