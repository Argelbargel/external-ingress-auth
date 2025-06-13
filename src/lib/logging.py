from datetime import datetime, timezone


class Logger:
    LEVEL = 'INFO'
    FORMAT = 'JSON'

    def __init__(self, object_name:str):
        self.object_name = object_name

    def error(self, message:str, **extra_fields):
        if self.LEVEL in ['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self._print('ERROR', message, extra_fields)

    def warning(self, message:str, **extra_fields):
        if self.LEVEL in ['TRACE', 'DEBUG', 'INFO', 'WARNING']:
            self._print('WARNING', message, extra_fields)

    def info(self, message:str, **extra_fields):
        if self.LEVEL in ['TRACE', 'DEBUG', 'INFO']:
            self._print('INFO', message, extra_fields)

    def debug(self, message:str, **extra_fields):
        if self.LEVEL in ['TRACE', 'DEBUG']:
            self._print('DEBUG', message, extra_fields)

    def trace(self, message:str, **extra_fields):
        if self.LEVEL in ['TRACE']:
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

        if self.FORMAT == 'JSON':
            print(str(fields))
        else:
            print(' - '.join(map(str, fields.values())))


def configure_logging(log_level:str='INFO', log_format:str='JSON'):
    Logger.LEVEL = log_level.upper()
    Logger.FORMAT = log_format.upper()
