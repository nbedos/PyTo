import unittest

from pyto.utilities import validate_structure


class TestUtilities(unittest.TestCase):
    def test_validate_structure(self):
        """Check _validate_structure() output against a few handmade cases"""
        # Call _validate_structure with twice the same object: it should always return True
        success_test_cases = [
            {'string': 'http://example.com/announce', 'int': 42, 'list': [1, 2]},
            {'dict': {'list': [1, 2, 3], 'int': 1}, 'str': 'str'},
        ]

        for test in success_test_cases:
            with self.subTest(test=test):
                self.assertTrue(validate_structure(test, test))

        # Dictionaries in 'data' are allowed to have keys missing from the schema
        self.assertTrue(validate_structure({'unused': 0, 'used': 1}, {'used': 1}))

        # Diverging data structures
        failure_test_cases = [
            ({'present': 0}, {'present': 0, 'missing': 1}),
            ([1, 2, 'string not int'], [1, 2, 3])
        ]

        for data, schema in failure_test_cases:
            with self.subTest(data=data, schema=schema):
                self.assertFalse(validate_structure(data, schema))


if __name__ == '__main__':
    unittest.main()
