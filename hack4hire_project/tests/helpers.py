import os
import shutil
import tempfile
import unittest

import models


class TempDbTestCase(unittest.TestCase):
    """Runs every test against its own throwaway database, never the real one"""

    def setUp(self):
        # Tests may call setUp again for a clean slate; only the first call saves the real path
        if not hasattr(self, '_original_db'):
            self._original_db = models.DATABASE_NAME
        tmpdir = tempfile.mkdtemp(prefix='allsafe-test-')
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        models.DATABASE_NAME = os.path.join(tmpdir, 'test.db')
        models.init_db()

    def tearDown(self):
        models.DATABASE_NAME = self._original_db
