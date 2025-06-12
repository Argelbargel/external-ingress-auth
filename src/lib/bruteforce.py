from cachetools import TTLCache

from .logging import Logger

class BruteForce:
    def __init__(self, enabled:bool, max_failures:int, expiration:int):
        self.enabled = enabled
        self.max_failures = max_failures
        self.database = TTLCache(float('inf'), expiration)

        self.logs = Logger(self.__class__.__name__)
        if (self.enabled):
            self.logs.info('brute-force-protection is enabled', failures=self.max_failures, expiration=expiration)

    def add_failure(self, ip):
        '''
            Increase IP failure
        '''
        if not self.enabled:
            return False

        failures = 1
        if ip in self.database:
            failures = self.database[ip] + 1

        self.logs.debug('increased authentication failures', ip=ip, failures=failures)
        self.database[ip] = failures

        if failures >= self.max_failures:
            return True

        return False

    def is_blocked(self, ip) -> bool:
        '''
            Returns True if the IP is blocked, False otherwise
        '''
        if not self.enabled:
            return False

        return ip in self.database and self.database[ip] >= self.max_failures
