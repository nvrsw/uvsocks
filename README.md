About
---

uvsocks is a reliable socks client implemented using [libuv](https://github.com/libuv/libuv) for windows and linux.

It has support forward and reverse mode.

More information about socks5 : [RFC1928](http://www.ietf.org/rfc/rfc1928.txt "RFC1928")

Building
---
1. Install the following build tools and dependencies:
* [Python 2.7](https://www.python.org/ftp/python/2.7.9/python-2.7.9.amd64.msi) (install in C:\Python27)

1. Clone [this repository](https://github.com/hsccr/uvsocks) It contains the build script, project files and patches.

1. Now start a git-command-line window as a regular user. Go to the uvsocks directory and start building with the script. For example, to build 'Libuv' and its dependencies, run:

  ```
  $git submodule init
  $git submodule update
  ```

To build the Windows:

  `Compile and Run a Project in Visual Studio 2015`

To build the Windows:


Usage
---
   uvsocks [-L listen:port:host:port]
           [-R listen:port:host:port]
           [-l login_name]
           [-a password]
           [-p port]
           [user:password@]hostname:port

Examples

`uvsocks -L 127.0.0.1:1234:192.168.0.231:8000 user:password@192.168.0.15:1080`

`uvsocks -L 127.0.0.1:1234:192.168.0.231:8000 192.168.0.15 -l user -a password -p 22`

`uvsocks -R 5824:192.168.0.231:8000 user:password@192.168.0.15:1080`

`uvsocks -R 5824:192.168.0.231:8000 192.168.0.15 -l user -a password -p 1080`

`uvsocks -L 127.0.0.1:1234:192.168.0.231:8000 -R 5824:192.168.0.231:8000 user:password@192.168.0.15:1080`

`uvsocks -L 127.0.0.1:1234:192.168.0.231:8000 -R 5824:192.168.0.231:8000 192.168.0.15 -l user -a password -p 1080`

---


