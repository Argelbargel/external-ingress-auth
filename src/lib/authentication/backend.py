from collections.abc import Iterable
from ..logging import Logger


class AuthenticationBackend:
    def __init__(self):
        self._log = Logger(self.__class__.__name__)

    def authenticate(self, username:str, password:str) -> tuple[bool, Iterable[str]]:
        raise NotImplementedError()
    
    def health(self) -> bool:
        raise NotImplementedError()
