import ldap
import re
from itertools import repeat
from aldap.logs import Logs


class Aldap:
    def __init__(self, endpoint, bind_dn, search_base, search_filter, manager_dn, manager_password):
        self.ldap_endpoint = endpoint
        self.bind_dn = bind_dn
        self.search_base = search_base
        self.search_filter = search_filter
        self.manager_username = manager_dn
        self.manager_password = manager_password

        self.logs = Logs(self.__class__.__name__)
        self.logs.info({'message':f"Using {self.ldap_endpoint} for authentication", 'searchBase': self.search_base, 'searchFilter': self.search_filter })

    def authenticate(self, username:str, password:str) -> tuple[bool, list[str]]:
        '''
            Authenticate user by username and password
        '''
        if username and password:
            final_username = username
            if self.bind_dn:
                final_username = self.bind_dn.replace("{username}", username)

            conn = self._connect()
            try:
                self.logs.debug({'message': f'Binding as {final_username}...', 'username': username})
                conn.simple_bind_s(final_username, password)
                return True, self._search_groups(username)
            except ldap.INVALID_CREDENTIALS:
                pass
            except ldap.LDAPError as e:
                self.logs.warning({'message':'An error occurred while trying to bind', 'error': str(e), 'username': username})
            finally:
                conn.unbind()

        return False, []


    def authorize(self, user_name:str, user_groups:list, allowed_users = None, allowed_groups = None, cond_groups = 'or', cond_users_groups = 'or') -> tuple[bool, list[str]]:
        '''
            Authorize against allowed users and/or groups
        '''
        authorized = True
        groups = []

        # Check allowed users
        if allowed_users is not None:
            allowed_users = [x.strip() for x in allowed_users.split(',')]
            authorized = self._authorize_user(user_name, allowed_users)
            if not authorized and cond_users_groups == 'and':
                return False, []

        # Check allowed groups
        if allowed_groups is not None:
            allowed_groups = [x.strip() for x in allowed_groups.split(',')]
            authorized, groups = self._authorize_groups(user_groups, allowed_groups, cond_groups)

        return authorized, groups


    def health(self) -> bool:
        '''
            Check if connection to ldap-server is healthy
        '''
        conn = self._connect()
        try:
            conn.simple_bind_s(self.manager_username, self.manager_password)
        except ldap.LDAPError as e:
            self.logs.warning({'message':'Health-Check failed. An error occurred while trying to bind', 'error': str(e)})
            return False
        finally:
            conn.unbind()
        return True


    def _connect(self):
        '''
            Returns LDAP object instance by opening LDAP connection to LDAP host
        '''
        self.logs.debug({'message':'Connecting to LDAP server'})
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        connect = ldap.initialize(self.ldap_endpoint)
        connect.set_option(ldap.OPT_REFERRALS, 0)
        connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        return connect


    def _search_groups(self, username:str) -> list[str]:
        '''
            Returns user's groups
        '''
        groups = []
        conn = self._connect()
        try:
            self.logs.debug({'message':'Getting user\'s groups...', 'username': username})
            conn.simple_bind_s(self.manager_username, self.manager_password)
            search_filter = self.search_filter.replace("{username}", username)
            for zone in conn.search_s(self.search_base, ldap.SCOPE_SUBTREE, search_filter):
                for element in zone:
                    try:
                        groups.extend(element['memberOf'])
                    except Exception:
                        pass
        except ldap.LDAPError as e:
            self.logs.warning({'message':'An error occurred while searching for user', 'error': str(e), 'username': username})
        finally:
            conn.unbind()

        # Create a list from the elements and convert binary to str the items
        return list(map(lambda g: g.decode('utf-8'), groups))


    def _authorize_groups(self, candidates:list, allowed:list, cond:str='or') -> tuple[bool, list[str]]:
        '''
            Validate user's groups.
            Returns True and matched groups if the groups are valid for the user, False otherwise.
        '''
        if cond not in ['and', 'or']:
            self.logs.warning({'message':'Invalid group conditional', 'conditional': cond})
            return False, []

        # Get the groups from the AD if they are not send via parameters
        self.logs.debug({'message':'Validating groups.', 'allowedGroups': ','.join(allowed), 'conditional': cond})
        matched_groups = []
        matches_by_group = []
        for group in allowed:
            matches = list(filter(None,list(map(self._find_matching_groups, repeat(group), candidates))))
            if matches:
                matches_by_group.append((group,matches))
                matched_groups.extend(matches)

        # Condition OR, true if just 1 group match
        if cond == 'or':
            if len(matched_groups) > 0:
                self.logs.debug({'message':'At least one group is valid', 'matchedGroups': ','.join(matched_groups), 'allowedGroups': ','.join(allowed), 'conditional': cond})
                return True, matched_groups
        # Condition AND, true if all the groups match
        elif cond == 'and':
            if len(allowed) == len(matches_by_group):
                self.logs.debug({'message':'All groups are valid', 'matchedGroups': ','.join(matched_groups), 'allowedGroups': ','.join(allowed), 'conditional': cond})
                return True, matched_groups

        self.logs.info({'message':'No group matched', 'matchedGroups': ','.join(matched_groups), 'allowedGroups': ','.join(allowed), 'conditional': cond})
        return False, []


    def _find_matching_groups(self, group:str, ad_group:str) -> str:
        try:
            # Extract the Common Name from the string (letters, spaces, underscores and hyphens)
            ad_group = re.search(r'(?i)CN=((\w*\s?_?-?)*)', ad_group).group(1)
        except Exception as e:
            self.logs.warning({'message':'There was an error trying to search CN: %s' % e})
            return None

        ad_group = ad_group.lower()
        group = group.lower()

        # Return match against supplied group/pattern (None if there is no match)
        try:
            return re.fullmatch(f'{group}.*', ad_group).group(0)
        except AttributeError:
            return None


    def _authorize_user(self, username:str, allowed:list) -> bool:
        '''
            Validate if the user is inside the allowed-user list.
            Returns True if the user is inside the list, False otherwise.
        '''
        self.logs.debug({'message':'Validating allowed-users list.', 'username': username, 'allowedUsers': ','.join(allowed)})
        for user in allowed:
            if username.lower() == user.strip().lower():
                self.logs.debug({'message':'User in the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowed)})
                return True
        self.logs.info({'message':'User not found in the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowed)})
        return False

