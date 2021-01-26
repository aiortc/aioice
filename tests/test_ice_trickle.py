import asyncio
import unittest

from aioice import ice

from .utils import run


class IceTrickleTest(unittest.TestCase):
    def assertCandidateTypes(self, conn, expected):
        types = set([c.type for c in conn.local_candidates])
        self.assertEqual(types, expected)

    def test_connect(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite
        run(conn_a.gather_candidates())
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # accept
        run(conn_b.gather_candidates())
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password

        # we should only have host candidates
        self.assertCandidateTypes(conn_a, set(["host"]))
        self.assertCandidateTypes(conn_b, set(["host"]))

        # there should be a default candidate for component 1
        candidate = conn_a.get_default_candidate(1)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.type, "host")

        # there should not be a default candidate for component 2
        candidate = conn_a.get_default_candidate(2)
        self.assertIsNone(candidate)

        async def add_candidates_later(a, b):
            await asyncio.sleep(0.1)
            for candidate in b.local_candidates:
                await a.add_remote_candidate(candidate)
                await asyncio.sleep(0.1)
            await a.add_remote_candidate(None)

        # connect
        run(
            asyncio.gather(
                conn_a.connect(),
                conn_b.connect(),
                add_candidates_later(conn_a, conn_b),
                add_candidates_later(conn_b, conn_a),
            )
        )

        # send data a -> b
        run(conn_a.send(b"howdee"))
        data = run(conn_b.recv())
        self.assertEqual(data, b"howdee")

        # send data b -> a
        run(conn_b.send(b"gotcha"))
        data = run(conn_a.recv())
        self.assertEqual(data, b"gotcha")

        # close
        run(conn_a.close())
        run(conn_b.close())
