import ldap
import time
import re
from itertools import repeat
from aldap.logs import Logs
from aldap.parameters import Parameters

class Aldap:
    def __init__(self, endpoint, bind_dn, search_base, search_filter, manager_dn, manager_password):
        self.param = Parameters()
        self.logs = Logs(self.__class__.__name__)

        self.ldapEndpoint = endpoint
        self.bindDN = bind_dn
        self.searchBase = search_base
        self.searchFilter = search_filter
        self.dnUsername = manager_dn
        self.dnPassword = manager_password

        self.logs.info({'message':f"using {self.ldapEndpoint} for authentication", 'searchBase': self.searchBase, 'searchFilter': self.searchFilter }, False)

    def authenticate(self, username:str, password:str) -> bool:
        '''
            Authenticate user by username and password
        '''
        finalUsername = username
        if self.bindDN:
            finalUsername = self.bindDN.replace("{username}", username)

        self.logs.debug({'message':'Authenticating user via LDAP.', 'username': username, 'finalUsername': finalUsername})

        start = time.time()
        try:
            connect = self._connect()
            connect.simple_bind_s(finalUsername, password)
            end = time.time()-start
            self.logs.debug({'message':'Authentication successful via LDAP.', 'username': username, 'elapsedTime': str(end)})
            return True
        except ldap.INVALID_CREDENTIALS:
            self.logs.warning({'message':'Authentication failed via LDAP, invalid credentials.', 'username': username})
        except ldap.LDAPError as e:
            self.logs.error({'message':'There was an error trying to bind: %s' % e})

        return False


    def authorize(self, username:str, allowed_users = None, allowed_groups = None, cond_groups = 'or', cond_users_groups = 'or'):
        authorized = True
        groups = []

        # Check allowed users
        if allowed_users is not None:
            authorized = self._validateAllowedUsers(username, [x.strip() for x in allowed_users.split(',')])
            if not authorized and cond_users_groups == 'and':
                return False, []

        # Check allowed groups
        if allowed_groups is not None:
            authorized, groups = self._validateAllowedGroups(username, self._userGroups(username), [x.strip() for x in allowed_groups.split(',')], cond_groups)

        return authorized, groups

    def health(self):
        try:
            connect = self._connect()
            connect.simple_bind_s(self.dnUsername, self.dnPassword)
        except ldap.LDAPError as e:
            self.logs.warning({'message':'health-check failed: %s' % e})
            return False
        return True

    def _connect(self):
        '''
            Returns LDAP object instance by opening LDAP connection to LDAP host
        '''
        self.logs.debug({'message':'Connecting to LDAP server.'})
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        connect = ldap.initialize(self.ldapEndpoint)
        connect.set_option(ldap.OPT_REFERRALS, 0)
        connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        return connect

    def __getTree__(self, searchFilter:str) -> list:
        '''
            Returns the AD tree for the user, the user is search by the searchFilter
        '''
        result = []
        try:
            start = time.time()
            connect = self._connect()
            connect.simple_bind_s(self.dnUsername, self.dnPassword)
            result = connect.search_s(self.searchBase, ldap.SCOPE_SUBTREE, searchFilter)
            end = time.time()-start
            self.logs.debug({'message':'Searched by filter.', 'filter': searchFilter, 'elapsedTime': str(end)})
        except ldap.LDAPError as e:
            self.logs.error({'message':'There was an error trying to bind: %s' % e})

        return result

    def __decode__(self, word:bytes) -> str:
        '''
            Convert binary to string. b'test' => 'test'
        '''
        return word.decode("utf-8")

    def __findMatch__(self, group:str, adGroup:str):
        try:
            # Extract the Common Name from the string (letters, spaces, underscores and hyphens)
            adGroup = re.search(r'(?i)CN=((\w*\s?_?-?)*)', adGroup).group(1)
        except Exception as e:
            self.logs.warning({'message':'There was an error trying to search CN: %s' % e})
            return None

        adGroup = adGroup.lower()
        group = group.lower()

        # Return match against supplied group/pattern (None if there is no match)
        try:
            return re.fullmatch(f'{group}.*', adGroup).group(0)
        except:
            return None

    def _userGroups(self, username:str):
        '''
            Returns user's groups
        '''
        self.logs.debug({'message':'Getting user\'s groups.'})
        searchFilter = self.searchFilter.replace("{username}", username)
        tree = self.__getTree__(searchFilter)

        # Crawl tree and extract the groups of the user
        adGroups = []
        for zone in tree:
            for element in zone:
                try:
                    adGroups.extend(element['memberOf'])
                except:
                    pass
        # Create a list from the elements and convert binary to str the items
        adGroups = list(map(self.__decode__,adGroups))
        return adGroups

    def _validateAllowedGroups(self, username:str, groups:list, allowedGroups:list, condGroups:str='or'):
        '''
            Validate user's groups.
            Returns True and matched groups if the groups are valid for the user, False otherwise.
        '''
        # Get the groups from the AD if they are not send via parameters
        adGroups = groups
        if groups is None:
            adGroups = self.getUserGroups(username)

        self.logs.debug({'message':'Validating AD groups.', 'username': username, 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
        matchedGroups = []
        matchesByGroup = []
        for group in allowedGroups:
            matches = list(filter(None,list(map(self.__findMatch__, repeat(group), adGroups))))
            if matches:
                matchesByGroup.append((group,matches))
                matchedGroups.extend(matches)

        # Conditiona OR, true if just 1 group match
        if condGroups == 'or':
            if len(matchedGroups) > 0:
                self.logs.info({'message':'At least one group is valid for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
                return True, matchedGroups
        # Conditiona AND, true if all the groups match
        elif condGroups == 'and':
            if len(allowedGroups) == len(matchesByGroup):
                self.logs.info({'message':'All groups are valid for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
                return True, matchedGroups
        else:
            self.logs.warning({'message':'Invalid conditional group.', 'username': username, 'conditional': condGroups})
            return False, []

        self.logs.warning({'message':'Invalid groups for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
        return False, []

    def _validateAllowedUsers(self, username:str, allowedUsers:list):
        '''
            Validate if the user is inside the allowed-user list.
            Returns True if the user is inside the list, False otherwise.
        '''
        self.logs.debug({'message':'Validating allowed-users list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
        for user in allowedUsers:
            if username.lower() == user.strip().lower():
                self.logs.info({'message':'User inside the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
                return True
        self.logs.info({'message':'User not found inside the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
        return False

