from collections.abc import Iterable

from ..logs import Logs
from .rule import DEFAULT_RULE, Rule


class Rules:
    def __init__(self):
        self._log = Logs(self.__class__.__name__)

    def find_rule(self, host:str, ip:str, method:str, path:str):
        for rule in self.rules():
            if rule.applies(host, ip, method, path):
                self._log.debug("found rule matching the request", host=host, ip=ip, method=method, path=path, rule=rule)
                return rule
        self._log.info("no rule found matching the request, falling back to default-rule (user must be authenticated)", host=host, ip=ip, method=method, path=path, rule=DEFAULT_RULE)
        return DEFAULT_RULE

    def rules(self) -> Iterable[Rule]:
        return []

    def __eq__(self, o:'Rules'):
        if isinstance(o, Rules):
            return self.rules() == o.rules()
        return NotImplemented

    def __repr__(self):
        return str(self.rules())

    def __str__(self):
        return self.__repr__()


class RuleSet(Rules):
    def __init__(self, *rules:Iterable[Rule]):
        super().__init__()
        self._rules = []
        self.add_rules(*rules)

    def rules(self) -> Iterable[Rule]:
        return self._rules

    def add_rules(self, *rules:Iterable[Rule]):
        for rule in rules:
            if rule not in self._rules:
                self._rules.append(rule)
