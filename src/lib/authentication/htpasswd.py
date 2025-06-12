import re
from collections.abc import Iterable
from passlib.apache import HtpasswdFile

from ..utils import FileObserver
from .backend import AuthenticationBackend


class HtPasswd(AuthenticationBackend):
    def __init__(self, users_file:str, groups_file:str=None):
        super().__init__()
        self._users = UsersFile(users_file)
        self._groups = GroupsFile(groups_file) if groups_file else None

    def authenticate(self, username:str, password:str) -> tuple[bool, list[str]]:
        if username and password:
            if self._users.check_password(username, password):
                return username, self._groups.user_groups(username) if self._groups else []

        return False, []

    def health(self):
        return True


class UsersFile(FileObserver):
    def __init__(self, path:str, observer=None):
        self._users = HtpasswdFile()

        super().__init__(path, observer=observer)

        self._log.info(f"Using htpasswd from {path} for htpasswd-authentication (if present)...")

    def check_password(self, user:str, password:str) -> bool:
        return self._users.check_password(user, password)

    def _update(self, path:str):
        if not path:
            self._users = HtpasswdFile()
        else:
            try:
                self._users = HtpasswdFile(path, encoding="utf-8", autosave=False)
            except IOError as e:
                self._log.error(f"could not load users from {path}", error=str(e))


class GroupsFile(FileObserver):
    def __init__(self, path:str, observer=None):
        self._groups = {}
        super().__init__(path, observer=observer)

        self._log.info(f"Using groups-file from {path} for htpasswd-authentication (if present)...")

    def user_groups(self, username: str) -> Iterable[str]:
        if username not in self._groups:
            return set()
        return self._groups[username]

    def _update_contents(self, contents:str):
        new_groups = {}

        for line in (l.lstrip() for l in re.split(r"\n+", contents, flags=re.MULTILINE)):
            if not line or line.startswith("#"):
                continue

            group, users = re.split(r":\s*", line, maxsplit=1)
            for u in (u.replace("\\ ", " ") for u in re.split(r"(?<!\\) ", users.lstrip())):
                if u:
                    if not u in new_groups:
                        new_groups[u] = set()
                    new_groups[u].add(group)

        self._groups = new_groups
