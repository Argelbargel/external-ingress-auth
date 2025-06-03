import json
from datetime import datetime, timezone
from aldap.parameters import Parameters


class Logs:
    def __init__(self, object_name:str):
        self.param = Parameters()

        self.object_name = object_name
        self.level = self.param.get('LOG_LEVEL', default='INFO').upper()
        self.format = self.param.get('LOG_FORMAT', default='JSON').upper()

    def error(self, extra_fields:dict=None):
        if self.level in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self._print('ERROR', extra_fields)

    def warning(self, extra_fields:dict=None):
        if self.level in ['DEBUG', 'INFO', 'WARNING']:
            self._print('WARNING', extra_fields)

    def info(self, extra_fields:dict=None):
        if self.level in ['DEBUG', 'INFO']:
            self._print('INFO', extra_fields)

    def debug(self, extra_fields:dict=None):
        if self.level in ['DEBUG']:
            self._print('DEBUG', extra_fields)

    def _print(self, level:str, extra_fields:dict):
        fields = {
            'date': datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            'level': level,
            'objectName': self.object_name,
        }

        # Include extra fields custom by the user
        if extra_fields is not None:
            fields.update(extra_fields)

        if self.format == 'JSON':
            print(json.dumps(fields))
        else:
            print(' - '.join(map(str, fields.values())))
