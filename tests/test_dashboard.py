import os
import unittest
from kalpa.dashboard.app import app

class TestDashboardBackend(unittest.TestCase):

    def test_routes_registered(self):
        routes = [route.path for route in app.routes]
        self.assertIn("/", routes)
        self.assertIn("/api/status", routes)
        self.assertIn("/api/run", routes)
        self.assertIn("/api/bundles", routes)

if __name__ == "__main__":
    unittest.main()
