ptserver
=======

A server application for testing / documenting / debugging the old Paltalk
protocol and client.

This is still incomplete but largely functional.

Just build with the ``Makefile`` and enjoy.

Dependencies
------------

- sqlite3

Synopsis
--------

```
ptserver [-h] [-d database_file] [-p port] [-m max_connections]
         [-s server_ip] [-t connection_timeout] [-x external_ip]

The defaults are: -d ptserver.db -p 5001 -m 8192 -s 0.0.0.0 -t 120 -x 127.0.0.1

Note: the argument given for -m may be constrained by resource limits.
Also, the port used for room audio will be port + 1.
The port for HTTP will be port + 2 for non-root users.
external_ip is the IPv4 address the client should connect to.
```

``-x`` must be specified if you're running the client in a VM, or somewhere
other than localhost.

Getting Started
---------------

See the [wiki](https://github.com/thentenaar/ptserver/wiki#getting-started)
for information on various client versions, and other odds and ends you'll
need to get the most out of ``ptserver``.

Supported Features
------------------

See the [wiki](https://github.com/thentenaar/ptserver/Supported-Features)
for a breakdown of supported features by client version.

