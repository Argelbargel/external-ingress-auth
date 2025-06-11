from os import environ
environ['LOG_LEVEL'] = 'TRACE'

import unittest

from .rule import AUTHENTICATED, Rule
from .rules import RuleSet

unittest.util._MAX_LENGTH=2000


RULE1 = Rule(methods=['POST'])
RULE2 = Rule(hosts=["example.com"], users=["me"], groups=["test"])
RULE3 = Rule(users=["me"], groups=["test"])


class TestRuleset(unittest.TestCase):
    def test_constructor(self):
        ruleset = RuleSet(RULE1, RULE2, RULE3, RULE1)
        self.assertEqual([RULE1, RULE2, RULE3], ruleset.rules())

    def test_add_rules(self):
        ruleset = RuleSet()
        ruleset.add_rules(RULE1, RULE2, RULE3, RULE1)
        self.assertEqual([RULE1, RULE2, RULE3], ruleset.rules())

    def test_find_rules_falls_back_to_default_rule(self):
        ruleset = RuleSet()
        self.assertEqual(AUTHENTICATED, ruleset.find_rule("example.com", "127.0.0.1", "GET", "/public/file"))

    def test_find_rules(self):
        ruleset = RuleSet(RULE1, RULE2, RULE3)
        self.assertEqual(RULE1, ruleset.find_rule("example.com", "127.0.0.1", "POST", "/"))
        self.assertEqual(RULE2, ruleset.find_rule("example.com", "127.0.0.1", "GET", "/"))
        self.assertEqual(RULE3, ruleset.find_rule("test.org", "127.0.0.1", "GET", "/"))


if __name__ == '__main__':
    unittest.main()        