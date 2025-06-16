from collections.abc import Iterable
from ipaddress import ip_address, ip_network
from pathlib import PurePath

from ..logging import Logger


AND = "and"
ANY = "**"
AUTHENTICATED = "<authenticated>"
PUBLIC = "<public>"
FORBIDDEN = "<forbidden>"
OR = "or"

class Rule:
    def __init__(self, hosts:Iterable[str]=None, ranges:Iterable[str]=None,
                 methods:Iterable[str]=None, paths:Iterable[str]=None,
                 users:Iterable[str]=None, groups:Iterable[str]=None,
                 groups_op:str=None, users_groups_op:str=None):
        self._log = Logger(self.__class__.__name__)

        self._hosts = set([ANY])
        self._ranges = set([ip_network('0.0.0.0/0')])
        self._methods = set([ANY])
        self._paths = set([ANY])
        self._users = set([AUTHENTICATED])
        self._groups = set([ANY])
        self._groups_op = OR
        self._users_groups_op = AND

        if hosts is not None and ANY not in hosts:
            self._hosts = {h.lower() for h in hosts}

        if ranges is not None and ANY not in ranges:
            self._ranges = {ip_network(r) for r in ranges}

        if methods is not None and ANY not in methods:
            self._methods = {m.upper() for m in methods}

        if paths is not None and ANY not in paths:
            self._paths = set(paths)

        if FORBIDDEN not in (users or []) and PUBLIC not in (users or []):
            if users is not None and ANY not in users and AUTHENTICATED not in users:
                self._users = set(users)
            if groups is not None and ANY not in groups:
                self._groups = set(groups)

                self._groups_op = str(groups_op or OR).lower()
                self._users_groups_op = str(users_groups_op or AND).lower()
        else:
            if ANY in self._ranges and ANY in self._methods and ANY in self._paths:
                raise ValueError("forbidden or public rule must specify either ranges, methods or paths")
            self._users = set([FORBIDDEN if FORBIDDEN in users else PUBLIC])
            self._groups = self._groups_op = self._users_groups_op = None

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

    def is_forbidden(self):
        return FORBIDDEN in self._users

    def is_public(self):
        return PUBLIC in self._users

    def authorize(self, username:str, groups:Iterable[str]) -> tuple[bool, Iterable[str]]:
        if self.is_public():
            self._log.info('Resource is public', rule=self)
            return True, set()

        authorized = AUTHENTICATED in self._users or username.lower() in self._users
        if not authorized and self._users_groups_op == AND:
            self._log.debug("User is not authorized", username=username, rule=self)
            return False, set()

        matched_groups = set()
        if self._groups is None or ANY in self._groups:
            self._log.debug("User successfully authorized", username=username, rule=self)
        else:
            matched_groups = self._groups.intersection(set(groups))

            if self._groups_op == AND and matched_groups != self._groups:
                self._log.trace('Not all groups matched', username=username, groups=groups, matched_groups=matched_groups, rule=self)
                authorized = authorized and self._users_groups_op == OR
                matched_groups = set()
            elif len(matched_groups) < 1:
                self._log.debug('No groups matched', username=username, groups=groups, rule=self)
                authorized = authorized and self._users_groups_op == OR
            else:
                authorized = True

            if not authorized:
                self._log.debug("Not authorized because groups not valid but enforced", username=username, groups=groups, rule=self)
                return False, set()

            self._log.debug("Successfully authorized", username=username, matched_groups=matched_groups, rule=self)

        return authorized, matched_groups

    def __hash__(self):
        return hash((
                frozenset(self._hosts),
                frozenset(self._ranges),
                frozenset(self._methods),
                frozenset(self._paths),
                frozenset(self._users),
                frozenset(self._groups) if self._groups else None,
                self._groups_op if self._groups_op else OR,
                self._users_groups_op if self._users_groups_op else AND
            ))

    def __eq__(self, o):
        if isinstance(o, Rule):
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
            'users_groups_op': self._users_groups_op
        })

    def __str__(self):
        return self.__repr__()


DEFAULT_RULE = Rule()
