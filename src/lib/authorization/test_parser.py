import unittest

from ..logging import configure_logging
from .parser import parse_rule, parse_rules
from .rule import Rule, ANY, AND, OR
from .rules import RuleSet

unittest.util._MAX_LENGTH=2000
configure_logging(log_level='TRACE')


class TestRulesParser(unittest.TestCase):
    def test_parse_rule_empty(self):
        with self.assertRaises(ValueError):
            self.assertEqual(Rule(), parse_rule(""))

    def test_parse_rule_defaults(self):
        self.assertEqual(Rule(), parse_rule("**:**:**:**:**:**:OR:AND"))

    def test_parse_complete_rule(self):
        self.assertEqual(
            Rule(["example.com", "secure.host.org"], ["192.168.0.0/24", "10.0.0.0/16"], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "User, Name"], ["group1", "group2"], AND, AND),
            parse_rule("example.com,secure.host.org,:192.168.0.0/24,10.0.0.0/16:HEAD,GET:/test1/**,/test2/*:us\:er1,User\, Name :group1,group2,,:AND:AND")
        )

    def test_parse_partial_rule(self):
        self.assertEqual(
            Rule(["example.com", "secure.host.org"], [ANY], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "User, Name"], ["group1", "group2"]),
            parse_rule("example.com,secure.host.org,:**:HEAD,GET:/test1/**,/test2/*:us\:er1,User\, Name :group1,group2,,")
        )

    def test_parse_space(self):
        rules = "example.com:192.168.0.0/24,10.0.0.0/16:HEAD,GET:/test1/**,/test2/*:us\:er1,user2:group1,group2:AND:AND test.org:127.0.0.1:GET:**"
        self.assertEqual(
            RuleSet(
                Rule(["example.com"], ["192.168.0.0/24", "10.0.0.0/16"], ['HEAD', 'GET'], ["/test1/**", "/test2/*"], ["us:er1", "user2"], ["group1", "group2"], AND, AND),
                Rule(["test.org"], ["127.0.0.1/32"], ["GET"], ["**"], ["**"], ["**"], OR, AND)
            ),
            parse_rules(rules)
        )

    def test_parse_whitespace(self):
        rules = "first.example.com:**:GET  **:**:HEAD \n\n  third.net:**:POST"
        self.assertEqual(
            RuleSet(
                Rule(hosts=["first.example.com"], methods=["GET"]),
                Rule(methods=["HEAD"]),
                Rule(hosts=["third.net"], methods=["POST"]),
            ),
            parse_rules(rules)
        )

    def test_parse_escaped_whitespace(self):
        rules = "**:**:**:**:**:Group\ Name **:**:**:**:User\,\ Name,Another\ User"
        self.assertEqual(
            RuleSet(
                Rule(groups=["Group Name"]),
                Rule(users=["User, Name", "Another User"])
            ),
            parse_rules(rules)
        )


if __name__ == '__main__':
    unittest.main()        