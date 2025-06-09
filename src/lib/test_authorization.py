from os import environ, unlink
environ['LOG_LEVEL'] = 'TRACE'

import unittest
from os.path import dirname, isfile
from time import sleep
from tempfile import NamedTemporaryFile

from .authorization import AuthorizationRule, AuthorizationRuleset, AuthorizationRulesParser, AuthorizationRulesFile, ANY, AND, DEFAULT_RULE, OR, PUBLIC

unittest.util._MAX_LENGTH=2000


class TestRuleEquality(unittest.TestCase):
    def test_same_rule_equals(self):
        self.assertEqual(DEFAULT_RULE, DEFAULT_RULE)

    def test_default_rule_equals(self):
        self.assertEqual(DEFAULT_RULE, AuthorizationRule())

    def test_complete_rule_equals(self):
        rule1 = AuthorizationRule(['example.com'], ["127.0.0.1", "192.168.0.0/16"], ["GET", "HEAD"], ["/**/file", "/dir/*"], ["user1", "user2"], ["group1", "group2"])
        rule2 = AuthorizationRule(['example.com'], ["192.168.0.0/16", "127.0.0.1"], ["HEAD", "GET"], ["/dir/*", "/**/file"], ["user2", "user1"], ["group2", "group1"])
        self.assertEqual(rule1, rule2)

    def test_inequality(self):
        rule1 = AuthorizationRule(["example.com"], [ANY], ["HEAD"], ["/**/file", "/dir/*"], ["user1", "user2"], ["group1", "group2"])
        rule2 = AuthorizationRule([ANY], [ANY], ["GET"])
        self.assertNotEqual(rule1, rule2)


class TestDefaultRule(unittest.TestCase):
    def test_default_values(self):
        self.assertEqual(DEFAULT_RULE, DEFAULT_RULE)
        self.assertEqual(AuthorizationRule(), DEFAULT_RULE)
        self.assertEqual(DEFAULT_RULE, AuthorizationRule(['**'], ['**'], ['**'], ['**'], ['**'], ['**'], OR, AND))

    def test_applies(self):
        self.assertTrue(DEFAULT_RULE.applies("example.com", '127.0.0.1', "GET", "/"))
        self.assertTrue(DEFAULT_RULE.applies("127.0.0.1", '192.168.10.2',"POST", "/path"))
        self.assertTrue(DEFAULT_RULE.applies("example.com", '127.0.0.1', "PUT", "/path"))
        self.assertTrue(DEFAULT_RULE.applies("", '127.0.0.1', "CUSTOM", "/path"))

    def test_is_public(self):
        self.assertFalse(DEFAULT_RULE.is_public())

    def test_authorize(self):
        authorized, groups = DEFAULT_RULE.authorize('', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)


class TestPublicRule(unittest.TestCase):
    RULE = AuthorizationRule(users=[PUBLIC])

    def test_values(self):
        self.assertEqual(self.RULE, AuthorizationRule(users=[PUBLIC], groups=None, groups_op=None, users_groups_op=None))
        self.assertEqual(self.RULE, AuthorizationRule(users=[PUBLIC], groups=['ignored'], groups_op=AND, users_groups_op=AND))

    def test_is_public(self):
        self.assertTrue(self.RULE.is_public())

    def test_authorize(self):
        authorized, groups = self.RULE.authorize('', [])
        self.assertTrue(authorized)
        self.assertEqual(set(), groups)


class TestHostsRule(unittest.TestCase):
    RULE = AuthorizationRule(hosts=["*.example.com", "test.org"])

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
    RULE = AuthorizationRule(ranges=["192.168.0.0/24", "172.12.0.0/24"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '192.168.0.1', "GET", "/"))
        self.assertFalse(self.RULE.applies("example.com", '192.168.1.1', "GET", "/"))
        self.assertTrue(self.RULE.applies("example.com", '172.12.0.1', "GET", "/"))
        self.assertFalse(self.RULE.applies("example.com", '10.12.10.34', "GET", "/"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestMethodsRule(unittest.TestCase):
    RULE = AuthorizationRule(methods=["HEAD", "GET"])

    def test_applies(self):
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "HEAD", "/"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/"))
        self.assertTrue(self.RULE.applies("example.com", '127.0.0.1', "GET", "/path"))
        self.assertTrue(self.RULE.applies("example.com", '192.168.1.2', "GET", "/path"))
        self.assertFalse(self.RULE.applies("example.com", '172.12.0.1', "POST", "/"))

    def test_is_public(self):
        self.assertFalse(self.RULE.is_public())


class TestPathsRule(unittest.TestCase):
    RULE = AuthorizationRule(paths=["/public/**", "/texts/**/*.txt", "/files/*"])

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
    RULE = AuthorizationRule(users=['user1', 'user2'])

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
    RULE = AuthorizationRule(groups=['group1', 'group2'], groups_op=OR)

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
    RULE = AuthorizationRule(groups=['group1', 'group2'], groups_op=AND)

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
    RULE = AuthorizationRule(users=['user1', 'user2'], groups=['group1', 'group2'], groups_op=OR, users_groups_op=AND)

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
    RULE = AuthorizationRule(users=['user1', 'user2'], groups=['group1', 'group2'], groups_op=AND, users_groups_op=AND)

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


class AuthorizationRulesetTest(unittest.TestCase):
    def test_initial_ruleset(self):
        ruleset = AuthorizationRuleset()
        self.assertEqual((DEFAULT_RULE,), ruleset.rules())

    def test_constructor(self):
        expected = (AuthorizationRule(methods=['GET']), AuthorizationRule(users=["me"]), DEFAULT_RULE)
        ruleset = AuthorizationRuleset(expected[0], expected[1])
        ruleset.add_rules(expected[0], expected[1])
        self.assertEqual(expected, ruleset.rules())

    def test_add_rules(self):
        ruleset = AuthorizationRuleset()
        expected = (AuthorizationRule(methods=['GET']), AuthorizationRule(users=["me"]), DEFAULT_RULE)
        ruleset.add_rules(expected[0], expected[1])
        self.assertEqual(expected, ruleset.rules())

    def test_add_DEFAULT_RULE(self):
        ruleset = AuthorizationRuleset()
        ruleset.add_rules(DEFAULT_RULE)
        self.assertEqual((DEFAULT_RULE,), ruleset.rules())

    def test_add_existing_rule(self):
        rule = AuthorizationRule(methods=['GET'])
        ruleset = AuthorizationRuleset(rule)
        ruleset.add_rules(rule)
        self.assertEqual(AuthorizationRuleset(rule), ruleset)
        self.assertEqual((rule, DEFAULT_RULE), ruleset.rules())

    def test_combine_empty_ruleset(self):
        ruleset1 = AuthorizationRuleset()
        ruleset2 = AuthorizationRuleset()
        combined = ruleset2.combine(ruleset1)
        self.assertEqual(AuthorizationRuleset(), combined)
        self.assertEqual((DEFAULT_RULE,), combined.rules())

    def test_combine(self):
        expected = (AuthorizationRule(methods=['GET']), AuthorizationRule(users=["me"]), AuthorizationRule(users=['you']), DEFAULT_RULE)
        ruleset1 = AuthorizationRuleset(expected[0], expected[1])
        ruleset2 = AuthorizationRuleset(expected[1], expected[2])
        combined = ruleset1.combine(ruleset2)
        self.assertEqual(AuthorizationRuleset(expected[0], expected[1], expected[2]), combined)
        self.assertEqual(expected, combined.rules())

    def test_rules(self):
        expected = (AuthorizationRule(methods=['GET']), AuthorizationRule(users=["me"]), DEFAULT_RULE)
        ruleset = AuthorizationRuleset(*expected)
        self.assertEqual(expected, ruleset.rules())


class AuthorizationRulesParserTest(unittest.TestCase):
    PARSER = AuthorizationRulesParser()

    def test_parse_rule_empty(self):
        self.assertEqual(AuthorizationRule(), self.PARSER.parse_rule(None))
        self.assertEqual(AuthorizationRule(), self.PARSER.parse_rule(""))

    def test_parse_rule_defaults(self):
        self.assertEqual(AuthorizationRule(), self.PARSER.parse_rule("**:**:**:**:**:**:OR:AND"))

    def test_parse_complete_rule(self):
        self.assertEqual(
            AuthorizationRule(["example.com", "secure.host.org"], ["192.168.0.0/24", "10.0.0.0/16"], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "User, Name"], ["group1", "group2"], AND, AND),
            self.PARSER.parse_rule("example.com,secure.host.org,:192.168.0.0/24,10.0.0.0/16:HEAD,GET:/test1/**,/test2/*:us\:er1,User\, Name :group1,group2,,:AND:AND")
        )

    def test_parse_partial_rule(self):
        self.assertEqual(
            AuthorizationRule(["example.com", "secure.host.org"], [ANY], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "User, Name"], ["group1", "group2"]),
            self.PARSER.parse_rule("example.com,secure.host.org,:**:HEAD,GET:/test1/**,/test2/*:us\:er1,User\, Name :group1,group2,,")
        )

    def test_parse_space(self):
        rules = "example.com:192.168.0.0/24,10.0.0.0/16:HEAD,GET:/test1/**,/test2/*:us\:er1,user2:group1,group2:AND:AND test.org:127.0.0.1:GET:**"
        self.assertEqual(
            AuthorizationRuleset(
                AuthorizationRule(["example.com"], ["192.168.0.0/24", "10.0.0.0/16"], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "user2"], ["group1", "group2"], AND, AND),
                AuthorizationRule(["test.org"], ["127.0.0.1/32"], ["GET"], ["**"], ["**"], ["**"], OR, AND)
            ),
            self.PARSER.parse(rules)
        )

    def test_parse_whitespace(self):
        rules = "first.example.com:**:GET  **:**:HEAD \n\n  third.net:**:POST"
        self.assertEqual(
            AuthorizationRuleset(
                AuthorizationRule(hosts=["first.example.com"], methods=["GET"]),
                AuthorizationRule(methods=["HEAD"]),
                AuthorizationRule(hosts=["third.net"], methods=["POST"]),
            ),
            self.PARSER.parse(rules)
        )

    def test_parse_escaped_whitespace(self):
        rules = "**:**:**:**:**:Group\ Name **:**:**:**:User\,\ Name,Another\ User"
        self.assertEqual(
            AuthorizationRuleset(
                AuthorizationRule(groups=["Group Name"]),
                AuthorizationRule(users=["User, Name", "Another User"])
            ),
            self.PARSER.parse(rules)
        )


class TestAuthorizationRulesFile(unittest.TestCase):
    def test_missing_file(self):
        with NamedTemporaryFile(delete=True) as f:
            file = AuthorizationRulesFile(dirname(f.name) + "/missing.txt")
            self.assertEqual((DEFAULT_RULE,), file.rules())

    def test_existing_file(self):
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\nexample.com:**:GET:**:**:group")
            tmpfile.close()

            rules_file = AuthorizationRulesFile(tmpfile.name)
            self.assertEqual(
                (
                    AuthorizationRule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    AuthorizationRule(hosts=["example.com"], methods=["GET"], groups=["group"]),
                    DEFAULT_RULE
                ),
                rules_file.rules()
            )
        finally:
            unlink(tmpfile.name)

    def test_update(self):
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\n")
            tmpfile.close()

            rules_file = AuthorizationRulesFile(tmpfile.name)
            self.assertEqual(
                (
                    AuthorizationRule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    DEFAULT_RULE
                ),
                rules_file.rules()
            )

            with open(tmpfile.name, 'a+', encoding='utf-8') as f:
                f.write("example.com:**:GET:**:**:group\n")

            sleep(1)

            self.assertEqual(
                (
                    AuthorizationRule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    AuthorizationRule(hosts=["example.com"], methods=["GET"], groups=["group"]),
                    DEFAULT_RULE
                ),
                rules_file.rules()
            )

        finally:
            unlink(tmpfile.name)

    def test_update_removed(self):
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\n")
            tmpfile.close()

            rules_file = AuthorizationRulesFile(tmpfile.name)
            self.assertEqual(
                (
                    AuthorizationRule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    DEFAULT_RULE
                ),
                rules_file.rules()
            )

            unlink(tmpfile.name)

            sleep(1)

            self.assertEqual((DEFAULT_RULE, ), rules_file.rules())

        finally:
            if isfile(tmpfile.name):
                unlink(tmpfile.name)

    def test_update_created(self):
        with NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8") as f:
            file = dirname(f.name) + "/rules"
            try:
                rules_file = AuthorizationRulesFile(file)
                self.assertEqual((DEFAULT_RULE, ), rules_file.rules())

                with open(file, 'w+', encoding='utf-8') as r:
                    r.write("**:**:HEAD,GET:/public/**:<public>\n")

                sleep(1)

                self.assertEqual(
                    (
                        AuthorizationRule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                        DEFAULT_RULE
                    ),
                    rules_file.rules()
                )
            finally:
                if isfile(file):
                    unlink(file)


if __name__ == '__main__':
    unittest.main()        