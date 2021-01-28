Changelog
=========

.. currentmodule:: aioice

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
