from os import makedirs
from os.path import dirname, isfile, realpath
from watchdog.events import FileSystemEvent, FileSystemEventHandler, EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED
from watchdog.observers.polling import PollingObserver as Observer

from .rules import Rules, RuleSet
from .parser import parse_rules


class RulesFile(Rules, FileSystemEventHandler):
    EVENTS = [EVENT_TYPE_MOVED, EVENT_TYPE_DELETED, EVENT_TYPE_CREATED, EVENT_TYPE_MODIFIED]
    
    def __init__(self, path:str, observer=None):
        super().__init__()
        self._path = path
        self._log.info(f"Using authorization rules from {self._path}...")

        self._rules = RuleSet()
        self._update()

        monitor_path = dirname(self._path)

        makedirs(monitor_path, mode=0o755, exist_ok=True)

        self._observer = observer or Observer()
        self._observer.schedule(self, monitor_path, recursive=False)
        self._observer.start()
        self._log.debug(f"Monitoring {monitor_path} for file-system-events...")

    def find_rule(self, host, ip, method, path):
        return self._rules.find_rule(host, ip, method, path)

    def rules(self):
        return self._rules.rules()

    def on_any_event(self, event:FileSystemEvent):
        self._log.trace(f"Received filesystem-event {event}...")
        if event.event_type in self.EVENTS and realpath(event.src_path) == realpath(self._path):
            self._log.debug(f"Received filesystem-event {event} for rules-file...")
            current_rules = self._rules
            try:
                self._update()
            except IOError as e:
                self._rules = current_rules
                self._log.warning("could not update authorization rules", error=str(e))

    def _update(self):
        self._log.trace(f"updating authorization rules from {self._path}...")
        if not isfile(self._path):
            self._log.warning(f"authorization-rules-file {self._path} does not exist, clearing rules...")
            self._rules = RuleSet()
        else:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._rules = parse_rules(f.read())
                self._log.info("Successfully updated authorization rules", rulesCount=len(self._rules.rules()))

    def __hash__(self):
        return hash(self._path)