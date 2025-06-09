import re
from os import makedirs
from os.path import dirname, isfile
from ipaddress import ip_address, ip_network
from collections.abc import Iterable
from pathlib import PurePath
from watchdog.events import FileSystemEvent, FileSystemEventHandler, EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED
from watchdog.observers.polling import PollingObserver as Observer

from .logs import Logs

ANY = "**"
PUBLIC = "<public>"
OR = "or"
AND = "and"


class AuthorizationRule:
    def __init__(self, hosts:Iterable[str]=None, ranges:Iterable[str]=None, methods:Iterable[str]=None, paths:Iterable[str]=None, 
                 users:Iterable[str]=None, groups:Iterable[str]=None, groups_op:str=None, users_groups_op:str=None):
        self._log = Logs(self.__class__.__name__)

        self._hosts = frozenset([h.lower() for h in hosts] if hosts is not None and ANY not in hosts else [ANY])
        self._ranges = frozenset([ip_network(r) for r in ranges] if ranges is not None and ANY not in ranges else [ip_network('0.0.0.0/0')])
        self._methods = frozenset([m.upper() for m in methods] if methods is not None and ANY not in methods else [ANY])
        self._paths = frozenset(paths if paths is not None and ANY not in paths else [ANY])

        self._users = frozenset([ANY])
        if users is not None:
            if PUBLIC in users:
                self._users = frozenset([PUBLIC])
                self._groups = self._groups_op = self._users_groups_op = None
            elif ANY not in users:
                self._users = frozenset(users)

        if PUBLIC in self._users:
            self._log.trace("Ignoring invalid groups-settings for public rule")
        else:
            self._groups = frozenset(groups if groups is not None and ANY not in groups else [ANY])
            self._groups_op = str(groups_op or OR).lower()
            self._users_groups_op = str(users_groups_op or AND).lower()


    def applies(self, host:str, ip:str, method:str, path:str) -> bool:
        ip = ip_address(ip)

        if ANY not in self._hosts:
            applies = False
            host = PurePath(host)
            for h in self._hosts:
                if host.full_match(h):
                    self._log.trace("rule applies to host", host=host, rule=self)
                    applies = True
                    break

            if not applies:
                self._log.trace("rule does not apply to host", host=host, rule=self)
                return False

        for r in self._ranges:
            if ip in r:

                if ANY not in self._methods and method.upper() not in self._methods:
                    self._log.trace("rule does not apply to request-method", host=host, ip=ip, method=method, rule=self)
                    return False

                path = PurePath(path)
                for p in self._paths:
                    if path.full_match(p):
                        self._log.trace("rule does apply to request", host=host, ip=ip, method=method, path=path, rule=self)
                        return True
                    
        self._log.trace("rule does not apply to request", host=host, ip=ip, method=method, path=path, rule=self)
        return False

    def is_public(self):
        return PUBLIC in self._users

    def authorize(self, username:str, groups:Iterable[str]) -> tuple[bool, Iterable[str]]:
        if self.is_public():
            self._log.info('Resource is public', rule=self)
            return True, set()

        authorized = ANY in self._users or username.lower() in self._users
        if not authorized and self._users_groups_op == AND:
            self._log.debug("User is not authorized", username=username, rule=self)
            return False, set()

        if self._groups is None or ANY in self._groups:
            matched_groups = set()
            self._log.debug("User successfully authorized", username=username, rule=self)
        else:
            matched_groups = self._groups.intersection(set(groups))

            if self._groups_op == AND and matched_groups != self._groups:
                self._log.debug('Not authorized because not all groups match', username=username, groups=groups, rule=self)
                return False, set()

            if len(matched_groups) < 1:
                self._log.debug('Not authorized because no groups match', username=username, groups=groups, rule=self)
                return False, set()

            self._log.debug("Successfully authorized", username=username, groups=groups, rule=self)

        return authorized, matched_groups

    def __hash__(self):
        return hash((self._ranges, self._hosts, self._methods, self._paths, self._users, self._groups, self._groups_op, self._users_groups_op))

    def __eq__(self, o):
        if isinstance(o, AuthorizationRule):
            return self.__hash__() == o.__hash__()
        return NotImplemented

    def __repr__(self):
        return str({
            'hosts': self._hosts,
            'ranges': self._ranges,
            'methods': self._methods,
            'paths': self._paths,
            'users': self._users,
            'groups': self._groups,
            'groups_op': self._groups_op,
            'users_groups_op': self._users_groups_op,
        })

    def __str__(self):
        return self.__repr__()

class AuthorizationRules:
    def find_rule(self, host:str, ip:str, method:str, path:str):
        raise NotImplementedError(f"find_rules not implemented in {self}")

    def combine(self, other:'AuthorizationRules'):
        raise NotImplementedError(f"find_rules not implemented in {self}")

    def rules(self):
        return ()


class AuthorizationRuleset(AuthorizationRules):
    def __init__(self, *rules:Iterable[AuthorizationRule]):
        self._rules = [DEFAULT_RULE]
        self._log = Logs(self.__class__.__name__)

        if rules:
            self.add_rules(*rules)

    def find_rule(self, host:str, ip:str, method:str, path:str):
        for rule in self._rules:
            if rule.applies(host, ip, method, path):
                self._log.debug("found rule matching the request", host=host, ip=ip, method=method, path=path, rule=rule)
                return rule
        raise LookupError("could not find any rule", host=host, ip=ip, method=method, path=path)

    def combine(self, other:AuthorizationRules) -> AuthorizationRules:
        self._log.trace("combining...")
        combined = AuthorizationRuleset()
        self._log.trace("adding rules from self...")
        combined.add_rules(*self.rules())
        self._log.trace("adding rules from other...")
        combined.add_rules(*other.rules())
        return combined

    def rules(self):
        return tuple(self._rules)

    def add_rules(self, *rules:Iterable[AuthorizationRule]):
        for rule in rules:
            if rule not in self._rules:
                self._log.trace("adding rule", rule=rule)
                self._rules.insert(len(self._rules) - 1, rule)
            else:
                self._log.trace("ignoring duplicate rule", rule=rule)

    def __hash__(self):
        return hash(self.rules())

    def __eq__(self, o):
        if isinstance(o, AuthorizationRuleset):
            return self.__hash__() == o.__hash__()
        return NotImplemented

    def __repr__(self):
        return str(self.rules())

    def __str__(self):
        return self.__repr__()


class AuthorizationRulesParser:
    PARTS_SEP = ":"
    PARTS_SEP_PATTERN = re.compile(r"(?<!\\)" + PARTS_SEP)
    PARTS_ELEM_SEP = ","
    PART_ELEM_SEP_PATTERN = re.compile(r"\s*(?<!\\),\s*")
    SEP = " "
    SEP_PATTERN = re.compile(r"(?<!\\)\s")


    def __init__(self):
        self._log = Logs(self.__class__.__name__)

    def parse(self, rules:str) -> AuthorizationRuleset:
        return self.parse_rules([p.replace(f"\\{self.SEP}", self.SEP) for p in re.split(self.SEP_PATTERN, rules.strip())])

    def parse_rules(self, rules:Iterable[str]) -> AuthorizationRuleset:
        ruleset = AuthorizationRuleset()
        for r in rules:
            try:
                ruleset.add_rules(self.parse_rule(r))
            except Exception as e:
                self._log.warning('Ignoring invalid rule', rule=r, error=e)
        return ruleset

    def parse_rule(self, rule:str) -> AuthorizationRule:
        if not rule or rule.startswith('#'):
            self._log.trace("Returning DEFAULT_RULE for empty string/None/comment")
            return DEFAULT_RULE
        
        parts = self._split(rule.strip(), self.PARTS_SEP, maxsplit=8)
        parts_len = len(parts)

        hosts = self._split(parts[0], self.PARTS_ELEM_SEP) if parts_len > 0 else None
        ranges = self._split(parts[1], self.PARTS_ELEM_SEP) if parts_len > 1 else None
        methods = self._split(parts[2], self.PARTS_ELEM_SEP) if parts_len > 2 else None
        paths = self._split(parts[3], self.PARTS_ELEM_SEP) if parts_len > 3 else None
        users = self._split(parts[4], self.PARTS_ELEM_SEP) if parts_len > 4 else None
        groups = self._split(parts[5], self.PARTS_ELEM_SEP) if parts_len > 5 else None
        groups_op =  parts[6] if parts_len > 6 else None
        user_groups_op = parts[7] if parts_len > 7 else None

        self._log.trace(f"Parsed {rule}", parts=parts, len=parts_len, hosts=hosts, ranges=ranges, methods=methods, paths=paths, users=users, groups=groups, groups_op=groups_op, user_groups_op=user_groups_op)
        return AuthorizationRule(hosts, ranges, methods, paths, users, groups, groups_op, user_groups_op)

    def _split(self, data:str, sep:str, maxsplit:int=0) -> Iterable[str]:
        return [
                re.sub(r"(?<!\\)\s+$", "", p).replace(f"\\{sep}", sep) \
                for p in re.split(f"(?<!\\\\){sep}", re.sub(f"(?<!\\\\){sep}+$", "", data.lstrip()), maxsplit=maxsplit)
            ]


class AuthorizationRulesFile(AuthorizationRules, FileSystemEventHandler):
    EVENTS = [EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED]
    
    def __init__(self, path:str, observer=None):
        self._path = path
        self._log = Logs(self.__class__.__name__)
        self._log.info(f"Using authorization rules from {self._path}...")

        self._rules = AuthorizationRuleset()
        self._update()

        monitor_path = dirname(self._path)

        makedirs(monitor_path, mode=0o755, exist_ok=True)

        self._observer = observer or Observer()
        self._observer.schedule(self, monitor_path, recursive=False)
        self._observer.start()
        self._log.debug(f"Monitoring {monitor_path} for file-system-events...")

    def find_rule(self, host, ip, method, path):
        return self._rules.find_rule(host, ip, method, path)

    def combine(self, other:AuthorizationRules):
        return self._rules.combine(other)
    
    def rules(self):
        return self._rules.rules()

    def on_any_event(self, event:FileSystemEvent):
        self._log.trace(f"Received filesystem-event {event}...")
        if event.event_type in self.EVENTS and event.src_path == self._path:
            self._log.debug(f"Received filesystem-event {event} for rules-file...")
            current_rules = self._rules
            try:
                self._update()
            except IOError as e:
                self._rules = current_rules
                self._log.warning("could not update authorization rules", error=str(e))

    def _update(self):
        self._log.trace(f"updating authorization rules from {self._path}...")
        if not isfile(self._path):
            self._log.warning(f"authorization-rules-file {self._path} does not exist, clearing rules...")
            self._rules = AuthorizationRuleset()
        else:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._rules = AuthorizationRulesParser().parse(f.read())
                self._log.info("Successfully updated authorization rules", rulesCount=len(self._rules.rules()))



DEFAULT_RULE = AuthorizationRule()
