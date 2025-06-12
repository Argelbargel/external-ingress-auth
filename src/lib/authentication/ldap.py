import ldap
from collections.abc import Iterable

from .backend import AuthenticationBackend


class LDAP(AuthenticationBackend):
    def __init__(self, endpoint, bind_dn, search_base, search_filter, manager_dn, manager_password):
        super().__init__()
        self.ldap_endpoint = endpoint
        self.bind_dn = bind_dn
        self.search_base = search_base
        self.search_filter = search_filter
        self.manager_username = manager_dn
        self.manager_password = manager_password

        self._log.info(f"Using {self.ldap_endpoint} for ldap-authentication", searchBase=self.search_base, searchFilter=self.search_filter)

    def authenticate(self, username:str, password:str) -> tuple[bool, Iterable[str]]:
        '''
            Authenticate user by username and password
        '''
        if username and password:
            final_username = username
            if self.bind_dn:
                final_username = self.bind_dn.replace("{username}", username)

            conn = self._connect()
            try:
                self._log.debug(f'Binding as {final_username}...', username=username)
                conn.simple_bind_s(final_username, password)
                return True, self._search_groups(username)
            except ldap.INVALID_CREDENTIALS:
                pass
            except ldap.LDAPError as e:
                self._log.warning('An error occurred while trying to bind', error=str(e), username=username)
            finally:
                conn.unbind()

        return False, []


    def health(self) -> bool:
        '''
            Check if connection to ldap-server is healthy
        '''
        conn = self._connect()
        try:
            conn.simple_bind_s(self.manager_username, self.manager_password)
        except ldap.LDAPError as e:
            self._log.warning('Health-Check failed. An error occurred while trying to bind', error=str(e))
            return False
        finally:
            conn.unbind()
        return True


    def _connect(self):
        '''
            Returns LDAP object instance by opening LDAP connection to LDAP host
        '''
        self._log.debug('Connecting to LDAP server...')
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
            self._log.debug("Getting user's groups...", username=username)
            conn.simple_bind_s(self.manager_username, self.manager_password)
            search_filter = self.search_filter.replace("{username}", username)
            for zone in conn.search_s(self.search_base, ldap.SCOPE_SUBTREE, search_filter):
                for element in zone:
                    try:
                        groups.extend(element['memberOf'])
                    except Exception:
                        pass
        except ldap.LDAPError as e:
            self._log.warning({'message':'An error occurred while searching for user', 'error': str(e), 'username': username})
        finally:
            conn.unbind()

        # Create a list from the elements and convert binary to str the items
        return list(map(lambda g: g.decode('utf-8'), groups))
