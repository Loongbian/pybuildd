# pybuildd

`pybuildd` is a reimplementation of Debian's original buildd in Python.
The choice of Python is primarily driven by it being portable to all
platforms Debian supports. At the same time the code aims to be more
accessible by having actual tests. The ultimate goal is to replace the
existing system completely. But you have to start somewhere.

Contrary to the old `buildd` implementation this one does not attempt
to implement any kind of service supervision. This is best placed outside
of the binary. This project includes a `systemd` service file and contributions
for other supervision systems like `runit` would be accepted if proposed.
This simplifies the application logic significantly.

## Caveats

This implementation currently aims to be compatible with the original buildd
by reusing some of the old interfaces. For instance it still talks to
wanna-build, which is difficult to set up.

The implementation also has to be compatible with Debian stable and hence
python3.5 at the time of writing. This means that some newer functionality
might not be available. The source hence contains some workarounds.
