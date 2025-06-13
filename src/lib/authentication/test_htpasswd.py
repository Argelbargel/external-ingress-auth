import unittest
from os import unlink
from random import choices
from string import ascii_letters, digits
from tempfile import TemporaryDirectory
from time import sleep
from watchdog.observers import Observer
from passlib.apache import HtpasswdFile

from ..logging import configure_logging
from .htpasswd import HtPasswd, UsersFile, GroupsFile

configure_logging(log_level='TRACE')

USER1 = "user1"
USER2 = "user2"
UNKNOWN_USER = "unknown"

PASSWORD1 = ''.join(choices(ascii_letters + digits, k=12))
PASSWORD2 = ''.join(choices(ascii_letters + digits, k=12))

GROUP1 = "group1"
GROUP2 = "group2"
GROUP3 = "group3"

def write_htpasswd_file(path: str, users:dict, new:bool=True):
    htpasswd_file = HtpasswdFile(new=new)
    for user, password in users.items():
        htpasswd_file.set_password(user, password)
    htpasswd_file.save(path)

def write_groups_file(path: str, groups:dict, new:bool=True):
    with open(path, 'w' if new else 'a', encoding='utf-8') as f:
        for group, users in groups.items():
            f.write(f"{group}: {' '.join(users)}\n")


class TestUsersFile(unittest.TestCase):
    def test_check_password(self):
        with TemporaryDirectory() as d:
            path = f"{d}/.htpasswd"
            write_htpasswd_file(path, {USER1: PASSWORD1, USER2: PASSWORD2})

            file = UsersFile(path)
            self.assertTrue(file.check_password(USER1, PASSWORD1))
            self.assertTrue(file.check_password(USER2, PASSWORD2))

            self.assertFalse(file.check_password(USER1, PASSWORD2))
            self.assertFalse(file.check_password(UNKNOWN_USER, PASSWORD1))

    def test_missing_file(self):
        with TemporaryDirectory() as d:
            file = UsersFile(f"{d}/missing.file")
            self.assertFalse(file.check_password(USER1, PASSWORD1))

    def test_update(self):
        with TemporaryDirectory() as d:
            path = f"{d}/.htpasswd"
            write_htpasswd_file(path, {USER1: PASSWORD1})

            file = UsersFile(path, Observer())

            self.assertTrue(file.check_password(USER1, PASSWORD1))
            self.assertFalse(file.check_password(USER2, PASSWORD2))

            write_htpasswd_file(path, {USER2: PASSWORD2}, False)

            sleep(1)

            self.assertTrue(file.check_password(USER2, PASSWORD2))

    def test_remove(self):
        with TemporaryDirectory() as d:
            path = f"{d}/.htpasswd"
            write_htpasswd_file(path, {USER1: PASSWORD1})

            file = UsersFile(path, Observer())

            self.assertTrue(file.check_password(USER1, PASSWORD1))

            unlink(path)

            sleep(1)

            self.assertFalse(file.check_password(USER2, PASSWORD2))

    def test_create(self):
        with TemporaryDirectory() as d:
            path = f"{d}/.htpasswd"
            file = UsersFile(path, Observer())

            self.assertFalse(file.check_password(USER1, PASSWORD1))

            write_htpasswd_file(path, {USER1: PASSWORD1})

            sleep(1)

            self.assertTrue(file.check_password(USER1, PASSWORD1))


class TestGroupsFile(unittest.TestCase):
    def test_user_groups(self):
        with TemporaryDirectory() as d:
            path = f"{d}/groups"
            write_groups_file(path, {GROUP1: [USER1, USER2], GROUP2: [USER1]})

            file = GroupsFile(path)
            self.assertSetEqual({GROUP1, GROUP2}, file.user_groups(USER1))
            self.assertSetEqual({GROUP1,}, file.user_groups(USER2))
            self.assertSetEqual(set(), file.user_groups(UNKNOWN_USER))

    def test_missing_file(self):
        with TemporaryDirectory() as d:
            file = GroupsFile(f"{d}/missing.file")
            self.assertSetEqual(set(), file.user_groups(USER1))

    def test_update(self):
        with TemporaryDirectory() as d:
            path = f"{d}/groups"
            write_groups_file(path, {GROUP1: [USER1]})

            file = GroupsFile(path, Observer())

            self.assertSetEqual({GROUP1}, file.user_groups(USER1))

            write_groups_file(path, {GROUP2: [USER1]}, False)

            sleep(1)

            self.assertSetEqual({GROUP1, GROUP2}, file.user_groups(USER1))

    def test_remove(self):
        with TemporaryDirectory() as d:
            path = f"{d}/groups"
            write_groups_file(path, {GROUP1: [USER1]})

            file = GroupsFile(path, Observer())

            self.assertSetEqual({GROUP1}, file.user_groups(USER1))

            unlink(path)

            sleep(1)

            self.assertSetEqual(set(), file.user_groups(USER1))

    def test_create(self):
        with TemporaryDirectory() as d:
            path = f"{d}/groups"
            file = GroupsFile(path, Observer())

            self.assertSetEqual(set(), file.user_groups(USER1))

            write_groups_file(path, {GROUP1: [USER1]})

            sleep(1)

            self.assertSetEqual({GROUP1}, file.user_groups(USER1))


class TestHtPasswd(unittest.TestCase):
    def test_authenticate(self):
        with TemporaryDirectory() as d:
            users_path = f"{d}/.htpasswd"
            groups_path = f"{d}/groups"
            write_htpasswd_file(users_path, {USER1: PASSWORD1, USER2: PASSWORD2})
            write_groups_file(groups_path, {GROUP1: [USER1], GROUP2: [USER1]})

            htpasswd = HtPasswd(users_path, groups_path)

            authenticated, groups = htpasswd.authenticate(USER1, PASSWORD1)
            self.assertTrue(authenticated)
            self.assertSetEqual({GROUP1, GROUP2}, groups)

            authenticated, groups = htpasswd.authenticate(USER2, PASSWORD2)
            self.assertTrue(authenticated)
            self.assertSetEqual(set(), groups)

            authenticated, groups = htpasswd.authenticate(UNKNOWN_USER, PASSWORD1)
            self.assertFalse(authenticated)
            self.assertEqual([], groups)

            authenticated, groups = htpasswd.authenticate(None, PASSWORD1)
            self.assertFalse(authenticated)
            self.assertEqual([], groups)

            authenticated, groups = htpasswd.authenticate(USER1, "")
            self.assertFalse(authenticated)
            self.assertEqual([], groups)

    def test_health(self):
        with TemporaryDirectory() as d:
            users_path = f"{d}/.htpasswd"
            groups_path = f"{d}/groups"

            htpasswd = HtPasswd(users_path, groups_path)

            self.assertTrue(htpasswd.health())


if __name__ == '__main__':
    unittest.main()
      