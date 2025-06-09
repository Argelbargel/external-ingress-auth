from os import getenv
from datetime import datetime, timezone


class Logs:
    def __init__(self, object_name:str):
        self.object_name = object_name
        self.level = getenv('LOG_LEVEL', 'INFO').upper()
        self.format = getenv('LOG_FORMAT', 'JSON').upper()

    def error(self, message:str, **extra_fields):
        if self.level in ['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self._print('ERROR', message, extra_fields)

    def warning(self, message:str, **extra_fields):
        if self.level in ['TRACE', 'DEBUG', 'INFO', 'WARNING']:
            self._print('WARNING', message, extra_fields)

    def info(self, message:str, **extra_fields):
        if self.level in ['TRACE', 'DEBUG', 'INFO']:
            self._print('INFO', message, extra_fields)

    def debug(self, message:str, **extra_fields):
        if self.level in ['TRACE', 'DEBUG']:
            self._print('DEBUG', message, extra_fields)

    def trace(self, message:str, **extra_fields):
        if self.level in ['TRACE']:
            self._print('TRACE', message, extra_fields)

    def _print(self, level:str, message, extra_fields:dict):
        fields = {
            'date': datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            'level': level,
            'objectName': self.object_name,
            'message': message
        }

        # Include extra fields custom by the user
        if extra_fields is not None:
            fields.update(extra_fields)

        if self.format == 'JSON':
            print(str(fields))
        else:
            print(' - '.join(map(str, fields.values())))
