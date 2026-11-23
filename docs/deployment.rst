Deployment
==========

Limiting the UDP ports
----------------------

:meth:`~aioice.Connection.gather_candidates` binds a UDP socket on each local
address, letting the operating system choose its port. aioice has no setting
to restrict these ports, but on Linux the operating system takes them from the
ephemeral port range, which the ``net.ipv4.ip_local_port_range`` sysctl sets
for both IPv4 and IPv6. Each network namespace has its own range, so a
container can restrict its ports without affecting the host.

With Docker, set the range when starting the container:

.. code-block:: console

    $ docker run --sysctl net.ipv4.ip_local_port_range="40000 40099" ...

Docker does not allow this sysctl together with ``--network=host``.

With Kubernetes, ``net.ipv4.ip_local_port_range`` is a safe sysctl, which a pod
sets in its security context:

.. code-block:: yaml

    spec:
      securityContext:
        sysctls:
        - name: net.ipv4.ip_local_port_range
          value: "40000 40099"

Kubernetes does not allow this sysctl together with host networking either.

The range applies to every socket in the namespace whose port the operating
system chooses, not only those of aioice, so allow some headroom. On each local
address, a :class:`~aioice.Connection` uses one port per component. A TURN
server over UDP takes one more port per component, which must be free on every
address. When the range is exhausted, aioice logs at the INFO level that it
could not bind to the address, and gathers neither a host nor a
server-reflexive candidate on it.
