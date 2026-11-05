Changelog
=========

.. currentmodule:: aioice

0.13.0
------

 * Authenticate STUN responses to connectivity checks, consent checks and
   TURN requests, and discard those whose MESSAGE-INTEGRITY is missing or
   does not match, so that they cannot be forged without the password. A
   check rejected with an unsigned error now times out instead of failing at
   once.
 * Check the USERNAME of incoming requests even before the remote username
   fragment is known, reject requests which fail authentication with a 401
   (Unauthenticated) error, and do not sign the error responses to them.
 * Fail a TURN allocation with a `ConnectionError` when the server's response
   lacks LIFETIME, XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS, instead of
   raising a `KeyError`.
 * Close the TURN socket when refreshing the allocation fails, instead of
   letting the allocation expire while it is still in use.
 * Fail a TURN request when the server sends an error response without
   ERROR-CODE, instead of raising a `KeyError`.
 * Join the mDNS multicast group when it is first needed, so that a remote
   mDNS candidate is ignored on a host without multicast, instead of
   `Connection.add_remote_candidate()` raising an `OSError`.
 * Do not complete cancelled mDNS queries, which raised an
   `InvalidStateError` and could prevent the mDNS protocol from closing.
 * `stun.parse_message()` no longer takes a key, use the new
   `stun.Message.check_message_integrity()` instead.

0.12.1
------

 * Stop connectivity checks when the connection is closed, even if
   `Connection.connect()` was cancelled or is still waiting for
   end-of-candidates. In the latter case, `Connection.connect()` now raises
   a `ConnectionError` instead of never returning.
 * Ignore incoming checks once the connection is closing.
 * Close the TURN socket when deleting the allocation is cancelled, for
   instance when the event loop shuts down, and log a failed deletion as such
   rather than as a deleted allocation.

0.12.0
------

 * Only use relayed candidates with the relay transport policy: no host
   socket is created and no server-reflexive candidate is gathered. Without a
   TURN server, no candidates are gathered instead of raising an error.
 * Use the mapped address of the TURN allocation as the related address of
   relayed candidates, and hide it with the relay transport policy. A TURN
   allocation now fails if the server does not return its mapped address.
 * Keep the hostname of remote mDNS candidates in
   `Connection.remote_candidates` instead of replacing it with the resolved
   address.
 * Do not pair relayed candidates with remote mDNS candidates, and ignore
   remote mDNS candidates with the relay transport policy.
 * Handle end-of-candidates only once pending mDNS candidates are resolved.
 * Update a peer-reflexive candidate when it is later signalled, and ignore a
   remote candidate whose address is already known, instead of forming
   duplicate pairs.
 * Match incoming checks against IPv6 remote candidates which were not
   signalled in canonical form.
 * Copy remote candidates when they are added, so later changes to the
   caller's object do not affect the connection.
 * Ignore remote candidates added once the connection is closing.
 * Defer incoming checks until `Connection.connect()` is called, as handling
   them earlier could leave a pair stuck in progress.
 * Keep at most 100 incoming checks until `Connection.connect()` is called.
 * Document `TransportPolicy` in the API reference.

0.11.0
------

 * Drop support for Python 3.9 and 3.10, add support for Python 3.14 and 3.15.
 * Wait for the remote end-of-candidates indication before declaring ICE
   failed, so that trickled candidates are still checked. Signal it with
   `Connection.add_remote_candidate(None)`, otherwise `Connection.connect()`
   keeps waiting.
 * Complete ICE when end-of-candidates removes a component which received no
   remote candidates.
 * Trigger checks for frozen pairs when a Binding request is received for
   them.
 * Remove unchecked pairs instead of marking them as failed when a pair is
   nominated.
 * Only fail `Connection.recv()` when the socket of a nominated pair is lost.
 * Stop retransmitting once a STUN transaction has completed, which could
   raise an `InvalidStateError`.
 * Handle Data indications from the TURN server, which are used when a peer
   sends from a port with no channel bound.
 * Ignore sends on a closed TURN transport, report send errors to the
   protocol and recover from failed channel bindings.
 * Close the TURN socket when an allocation is cancelled.
 * Include the attributes in the representation of STUN messages.

0.10.2
------

 * Fix local ice-ufrag/ice-pwd validation.

0.10.1
------

 * Remove a `print()` statement which was accidentally added in 0.10.0.

0.10.0
------

 * Enforce full type annotations on all the code.
 * Allow creating a connection with ufrag and pwd.
 * Fix an `IndexError` when decoding an invalid XOR-MAPPED-ADDRESS.
 * Connect to TURN server in parallel to STUN checks and catch errors.

0.9.0
-----

 * Switch from `netifaces` to `ifaddr`.
 * Do not start candidate pair check if already started.

0.8.0
-----

 * Allow gathering only relay (STUN/TURN) candidates.
 * Use padding when sending over data over TCP.
 * Add support for Python 3.11.

0.7.7
-----

 * Close underlying transport when a TURN allocation is deleted.
 * Shutdown mDNS stack when it is no longer referenced.
 * Rewrite asynchronous tests as coroutines.

0.7.6
-----

 * Ensure `dnspython` version is at least 2.0.0.
 * Avoid 400 error when using TURN with concurrent sends.
 * Avoid error if a connection is lost before the local candidate is set.

0.7.5
-----

 * Emit an event when the ICE connection is closed.

0.7.4
-----

 * Perform mDNS resolution using an A query, as Firefox does not respond
   to ANY queries.
 * Use full module name to name loggers.

0.7.3
-----

 * Defer mDNS lock initialisation to avoid mismatched event-loops,
   fixes errors seen with uvloop.
 * Correctly gather STUN candidates when there are multiple components.

0.7.2
-----

 * Add support for resolving mDNS candidates.

0.7.1
-----

TURN
....

 * Use the LIFETIME attribute returned by the server to determine the
   time-to-expiry for the allocation.
 * Raise stun.TransactionFailed if TURN allocation request is rejected
   with an error.
 * Handle 438 (Stale Nonce) error responses.
 * Ignore STUN transaction errors when deleting TURN allocation.
 * Periodically refresh channel bindings.

0.7.0
-----

Breaking
........

 * Make :meth:`Connection.add_remote_candidate` a coroutine.
 * Remove the `Connection.remote_candidates` setter.
