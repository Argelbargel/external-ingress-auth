import re
from collections.abc import Iterable

from ..logging import Logger

from .rule import DEFAULT_RULE, Rule
from .rules import RuleSet

PARTS_SEP = ":"
PARTS_SEP_PATTERN = re.compile(r"(?<!\\)" + PARTS_SEP)
PARTS_ELEM_SEP = ","
PART_ELEM_SEP_PATTERN = re.compile(r"\s*(?<!\\),\s*")
SEP = " "
SEP_PATTERN = re.compile(r"(?<!\\)\s")

_log = Logger(__name__)

def parse_rules(data:str) -> RuleSet:
    rules = RuleSet()

    data = data.strip()
    if data:
        for rule in [r.replace(f"\\{SEP}", SEP) for r in re.split(SEP_PATTERN, data)]:
            if rule and not rule.startswith("#"):
                try:
                    rules.add_rules(parse_rule(rule))
                except Exception as e:
                    _log.warning('Ignoring invalid rule', rule=rule, error=e)

    return rules

def parse_rule(rule:str) -> Rule:
    if rule is None or not rule.strip():
        raise ValueError(f"cannot parse '{rule}' to rule")
    
    rule = rule.strip()
    if rule.lower() == "<authenticated>":
        return DEFAULT_RULE
    
    parts = _split(rule, PARTS_SEP, maxsplit=8)
    parts_len = len(parts)

    hosts = _split(parts[0], PARTS_ELEM_SEP) if parts_len > 0 else None
    ranges = _split(parts[1], PARTS_ELEM_SEP) if parts_len > 1 else None
    methods = _split(parts[2], PARTS_ELEM_SEP) if parts_len > 2 else None
    paths = _split(parts[3], PARTS_ELEM_SEP) if parts_len > 3 else None
    users = _split(parts[4], PARTS_ELEM_SEP) if parts_len > 4 else None
    groups = _split(parts[5], PARTS_ELEM_SEP) if parts_len > 5 else None
    groups_op =  parts[6] if parts_len > 6 else None
    user_groups_op = parts[7] if parts_len > 7 else None

    _log.trace(f"Parsed {rule}", parts=parts, len=parts_len, hosts=hosts, ranges=ranges, methods=methods, paths=paths, users=users, groups=groups, groups_op=groups_op, user_groups_op=user_groups_op)
    return Rule(hosts, ranges, methods, paths, users, groups, groups_op, user_groups_op)

def _split(data:str, sep:str, maxsplit:int=0) -> Iterable[str]:
    return [
            re.sub(r"(?<!\\)\s+$", "", p).replace(f"\\{sep}", sep) \
            for p in re.split(f"(?<!\\\\){sep}", re.sub(f"(?<!\\\\){sep}+$", "", data.lstrip()), maxsplit=maxsplit)
        ]
