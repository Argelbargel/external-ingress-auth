import json
from datetime import datetime, timezone
from aldap.http import HTTP
from aldap.parameters import Parameters


class Logs:
    def __init__(self, objectName:str):
        self.param = Parameters()
        self.http = HTTP()

        self.objectName = objectName
        self.level = self.param.get('LOG_LEVEL', default='INFO').upper()
        self.format = self.param.get('LOG_FORMAT', default='JSON').upper()

    def __print__(self, level:str, extraFields:dict, includeRequestIP:bool):
        fields = {
            'date': datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            'level': level,
            'objectName': self.objectName,
        }

        # Include request IP
        if includeRequestIP:
            fields['ip'] = self.http.getRequestIP()

        # Include extra fields custom by the user
        if extraFields is not None:
            fields.update(extraFields)

        if self.format == 'JSON':
            print(json.dumps(fields))
        else:
            print(' - '.join(map(str, fields.values())))

    def error(self, extraFields:dict=None, includeRequestIP:bool=True):
        if self.level in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self.__print__('ERROR', extraFields, includeRequestIP)

    def warning(self, extraFields:dict=None, includeRequestIP:bool=True):
        if self.level in ['DEBUG', 'INFO', 'WARNING']:
            self.__print__('WARNING', extraFields, includeRequestIP)

    def info(self, extraFields:dict=None, includeRequestIP:bool=True):
        if self.level in ['DEBUG', 'INFO']:
            self.__print__('INFO', extraFields, includeRequestIP)

    def debug(self, extraFields:dict=None, includeRequestIP:bool=True):
        if self.level in ['DEBUG']:
            self.__print__('DEBUG', extraFields, includeRequestIP)
