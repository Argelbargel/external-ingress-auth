import unittest
from os import environ
environ['LOG_LEVEL'] = 'TRACE'

from .rule import Rule, AND, ANY, AUTHENTICATED, OR, PUBLIC

unittest.util._MAX_LENGTH=2000


class TestRuleEquality(unittest.TestCase):
    def test_complete_rule_equals(self):
        rule1 = Rule(['example.com'], ["127.0.0.1", "192.168.0.0/16"], ["GET", "HEAD"], ["/**/file", "/dir/*"], ["user1", "user2"], ["group1", "group2"])
        rule2 = Rule(['example.com'], ["192.168.0.0/16", "127.0.0.1"], ["HEAD", "GET"], ["/dir/*", "/**/file"], ["user2", "user1"], ["group2", "group1"])
        self.assertEqual(rule1, rule2)

    def test_inequality(self):
        rule1 = Rule(["example.com"], [ANY], ["HEAD"], ["/**/file", "/dir/*"], ["user1", "user2"], ["group1", "group2"])
        rule2 = Rule([ANY], [ANY], ["GET"])
        self.assertNotEqual(rule1, rule2)


class TestDefaultRule(unittest.TestCase):
    RULE = Rule()

    def test_default_values(self):
        self.assertEqual(self.RULE, Rule(['**'], ['**'], ['**'], ['**'], [AUTHENTICATED], ['**'], OR, AND))

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/"))
        self.assertTrue(self.RULE.applies("127.0.0.1", '192.168.10.2',"POST", "/path"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "PUT", "/path"))
        self.assertTrue(self.RULE.applies("", '127.0.0.1', "CUSTOM", "/path"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)


class TestPublicRule(unittest.TestCase):
    RULE = Rule(users=[PUBLIC])

    def test_values(self):
        self.assertEqual(self.RULE, Rule(users=[PUBLIC], groups=None, groups_op=None, users_groups_op=None))
        self.assertEqual(self.RULE, Rule(users=[PUBLIC], groups=['ignored'], groups_op=AND, users_groups_op=AND))

    def test_is_public(self):
        self.assertTrue(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)


class TestHostsRule(unittest.TestCase):
    RULE = Rule(hosts=["*.example.com", "test.org"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("sub.example.com", "127.0.0.1", "GET", "/"))
        self.assertTrue(self.RULE.applies("another.example.com", "127.0.0.1", "GET", "/"))
        self.assertFalse(self.RULE.applies("example.com", "127.0.0.1", "GET", "/"))
        self.assertTrue(self.RULE.applies("test.org", "127.0.0.1", "GET", "/"))
        self.assertFalse(self.RULE.applies("sub.test.org", "127.0.0.1", "GET", "/"))
        self.assertFalse(self.RULE.applies("localhost", "127.0.0.1", "GET", "/"))
        self.assertFalse(self.RULE.applies("another-example.com", "127.0.0.1", "GET", "/"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestRangesRule(unittest.TestCase):
    RULE = Rule(ranges=["192.168.0.0/24", "172.12.0.0/24"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '192.168.0.1', "GET", "/"))
        self.assertFalse(self.RULE.applies("example.com", '192.168.1.1', "GET", "/"))
        self.assertTrue(self.RULE.applies("example.com", '172.12.0.1', "GET", "/"))
        self.assertFalse(self.RULE.applies("example.com", '10.12.10.34', "GET", "/"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestMethodsRule(unittest.TestCase):
    RULE = Rule(methods=["HEAD", "GET"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "HEAD", "/"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/path"))
        self.assertTrue(self.RULE.applies("example.com", '192.168.1.2', "GET", "/path"))
        self.assertFalse(self.RULE.applies("example.com", '172.12.0.1', "POST", "/"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestPathsRule(unittest.TestCase):
    RULE = Rule(paths=["/public/**", "/texts/**/*.txt", "/files/*"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "HEAD", "/public/users/me/"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/public/users/me/file.txt"))

        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "PUT", "/texts/docs/rules.txt"))
        self.assertFalse(self.RULE.applies("example.com", '127.0.0.1', "HEAD", "/texts/docs/README.md"))

        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/files/file.dat"))
        self.assertFalse(self.RULE.applies("example.com", '127.0.0.1', "GET", "/files/secure/secure.dat"))

        self.assertFalse(self.RULE.applies("example.com", '127.0.0.1', "HEAD", "/index.html"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestUserRule(unittest.TestCase):
    RULE = Rule(users=['user1', 'user2'])

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('invalid', [])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('user1', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('user2', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)


class TestGroupOrRule(unittest.TestCase):
    RULE = Rule(groups=['group1', 'group2'], groups_op=OR)

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [''])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('', ['invalid'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('', ['group1'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group1']), groups)

        authorized, groups = self.RULE.authorize('', ['group2'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group2']), groups)


class TestGroupANDRule(unittest.TestCase):
    RULE = Rule(groups=['group1', 'group2'], groups_op=AND)

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [''])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('', ['invalid', 'group1'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('', ['group1', 'group2'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group1', 'group2']), groups)

        authorized, groups = self.RULE.authorize('', ['group1', 'group2'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group1', 'group2']), groups)


class TestUserANDGroupORRule(unittest.TestCase):
    RULE = Rule(users=['user1', 'user2'], groups=['group1', 'group2'], groups_op=OR, users_groups_op=AND)

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [''])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('invalid', ['invalid'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('invalid', ['group1'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('user1', ['invalid'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('user2', ['group1'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group1']), groups)


class TestUserANDGroupANDRule(unittest.TestCase):
    RULE = Rule(users=['user1', 'user2'], groups=['group1', 'group2'], groups_op=AND, users_groups_op=AND)

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [''])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('invalid', ['invalid'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('invalid', ['group1'])
        self.assertFalse(authorized)
        self.assertEqual(set(), groups)

        authorized, groups = self.RULE.authorize('user1', ['invalid', 'group1', 'group2'])
        self.assertTrue(authorized)
        self.assertEqual(set(['group1', 'group2']), groups)


if __name__ == '__main__':
    unittest.main()        