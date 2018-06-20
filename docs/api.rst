API Reference
=============

.. automodule:: aioice

   .. autoclass:: Connection
      :members: local_candidates, local_username, local_password, remote_candidates, remote_username, remote_password

      .. automethod:: add_remote_candidate
      .. autocomethod:: gather_candidates
      .. automethod:: get_default_candidate
      .. autocomethod:: connect
      .. autocomethod:: close
      .. autocomethod:: recv
      .. autocomethod:: recvfrom
      .. autocomethod:: send
      .. autocomethod:: sendto
      .. autocomethod:: set_selected_pair

   .. autoclass:: Candidate

      .. automethod:: from_sdp
      .. automethod:: to_sdp
