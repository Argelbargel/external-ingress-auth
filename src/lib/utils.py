from os import makedirs
from os.path import dirname, isdir, isfile, realpath

from watchdog.events import FileSystemEvent, FileSystemEventHandler, EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED
from watchdog.observers.polling import PollingObserver as Observer

from .logging import Logger


class FileObserver(FileSystemEventHandler):
    EVENTS = [EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED]

    def __init__(self, path:str, encoding:str='utf-8', observer=None):
        super().__init__()
        self._path = path
        self._encoding = encoding

        self._log = Logger(self.__class__.__name__)

        self.__update()

        monitor_path = dirname(self._path)

        if not isdir(monitor_path):
            makedirs(monitor_path, mode=0o755, exist_ok=True)

        self._observer = observer or Observer()
        self._observer.schedule(self, monitor_path, recursive=False)
        self._observer.start()

        self._log.debug(f"Monitoring {monitor_path} for file-system-events...")

    def on_any_event(self, event:FileSystemEvent):
        self._log.trace(f"Received filesystem-event {event}...")
        if event.event_type in self.EVENTS and realpath(event.src_path) == realpath(self._path):
            self._log.debug(f"Received filesystem-event {event} for {self._path}...")
            self.__update()

    def __update(self):
        self._update(self._path if isfile(self._path) else None)

    def _update(self, path:str):
        try:
            if not path:
                self._update_contents('')
            else:
                with open(path, mode='r', encoding=self._encoding) as f:
                    self._update_contents(f.read().strip())
        except IOError as e:
            self._log.warning("could not update", error=str(e))

    def _update_contents(self, contents:str):
        pass

    def __hash__(self):
        return hash(self._path)
