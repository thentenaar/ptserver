ptserver
=======

A server application for testing / documenting / debugging the old Paltalk
protocol and client.

This is still incomplete but largely functional.

Just build with the ``Makefile`` and enjoy.

Dependencies
------------

- sqlite3

Prerequisites
-------------

You'll want to add the following to your ``/etc/hosts`` (or
``C:\windows\system32\drivers\etc\hosts`` for the client. Substitute
``127.0.0.1`` for the IP address of the machine running the server:

```
127.0.0.1   www.paltalk.com
127.0.0.1   advertising.paltalk.com
127.0.0.1   router.paltalk-entry.com
127.0.0.1   pt-entry.paltalk.com
127.0.0.1   register.paltalk.com
127.0.0.1   connect.paltalk.com
127.0.0.1   connect.paltalkconnect.com
127.0.0.1   qos.paltalkconnect.com
127.0.0.1   client.paltalk.com
127.0.0.1   games.paltalk.com
127.0.0.1   download.paltalk.com
127.0.0.1   people.paltalk.com
127.0.0.1   centurylink.paltalk.com
127.0.0.1   my.paltalk.com
127.0.0.1   support.paltalk.com
127.0.0.1   home.paltalk.com
127.0.0.1   www.palpersonals.com
127.0.0.1   trk.kissmetrics.com
127.0.0.1   www.google-analytics.com
```

Setup
-----

Once you have the server running, and the client installed, try to
register a new user. For 5.1, you'll have to login as "newuser", since
they removed the usual means of getting to the registration dialog, and
the registration form will appear shortly thereafter; provided the client
can connect to the server.

