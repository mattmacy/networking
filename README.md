SpectraLogic async COW and dbuf refactoring:
-------------------------------------------

NOTES:
- spa async stuff still needed?  this is for config updates?
- spa history logging stuff might have gone upstream already

TODO (either simple or required for async cow):
- refactor out txg thread name change
- refactor out txg / sync context changes (probable conflict upstream)
- refactor out dmu context changes
- refactor out dbuf dirty state changes
- port forward async cow specific bits

TODO LATER:
- device arrival/departure notifications
- runtime tunable KMEM_DEBUG stuff
- lowmem improvements (may have been implemented another way elsewhere)
- bitbucket & zero region optimizations for vdev i/o aggregation
- any/all useful userland tool improvements
- znode kstats?
- SMR related changes?  these are incomplete iirc
- making invalid data non-fatal events
  - zfs_panic_recover -> DTRACE_INVALID_BP, etc.
- nosuspend stuff (prevents locking up other pools due to one)
- security descriptor / SID support for vfs/zfs
- vdev_file optimizations
- spare handling improvements

DROP:
- zrlock change (already sent upstream and ignored, seems unnoticed)
- all the zvol-related changes (including callbacks), just too much.  or
  maybe replace with a simpler update to current zvol layer?
- all ctldir changes (replaced by avg's work upstream)

===================================================================

FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.  This file
was last revised on:
$FreeBSD$

FreeBSD is an operating system used to power modern servers,
desktops, and embedded platforms. A large community has
continually developed it for more than thirty years. Its
advanced networking, security, and storage features have
made FreeBSD the platform of choice for many of the
busiest web sites and most pervasive embedded networking
and storage devices.

For copyright information, please see the file COPYRIGHT in this
directory. Additional copyright information also exists for some
sources in this tree - please see the specific source directories for
more information.

The Makefile in this directory supports a number of targets for
building components (or all) of the FreeBSD source tree.  See build(7), config(8),
https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/makeworld.html, and
https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/kernelconfig.html
for more information, including setting make(1) variables.

Source Roadmap:
---------------
```
bin		System/user commands.

cddl		Various commands and libraries under the Common Development
		and Distribution License.

contrib		Packages contributed by 3rd parties.

crypto		Cryptography stuff (see crypto/README).

etc		Template files for /etc.

gnu		Various commands and libraries under the GNU Public License.
		Please see gnu/COPYING* for more information.

include		System include files.

kerberos5	Kerberos5 (Heimdal) package.

lib		System libraries.

libexec		System daemons.

release		Release building Makefile & associated tools.

rescue		Build system for statically linked /rescue utilities.

sbin		System commands.

secure		Cryptographic libraries and commands.

share		Shared resources.

stand		Boot loader sources.

sys		Kernel sources.

sys/<arch>/conf Kernel configuration files. GENERIC is the configuration
		used in release builds. NOTES contains documentation of
		all possible entries.

tests		Regression tests which can be run by Kyua.  See tests/README
		for additional information.

tools		Utilities for regression testing and miscellaneous tasks.

usr.bin		User commands.

usr.sbin	System administration commands.
```

For information on synchronizing your source tree with one or more of
the FreeBSD Project's development branches, please see:

  https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/current-stable.html
