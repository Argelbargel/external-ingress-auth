from ..utils import FileObserver
from .rules import Rules, RuleSet
from .parser import parse_rules

class RulesFile(FileObserver, Rules):
    def __init__(self, path:str, observer=None):
        self._rules = RuleSet()

        super().__init__(path, observer=observer)
        Rules.__init__(self)

        self._log.info(f"Using authorization rules from {path}...")

    def find_rule(self, host, ip, method, path):
        return self._rules.find_rule(host, ip, method, path)

    def rules(self):
        return self._rules.rules()

    def _update_contents(self, contents:str):
        self._log.debug("updating authorization rules...")
        if not contents:
            self._log.warning("authorization-rules-file does not exist, clearing rules...")
            self._rules = RuleSet()
        else:
            self._rules = parse_rules(contents)
            self._log.info("Successfully updated authorization rules", rulesCount=len(self._rules.rules()))
