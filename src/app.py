from os import getenv
from urllib.parse import urlparse

from flask import Flask
from flask import abort, request, render_template
from werkzeug.exceptions import HTTPException
from cachetools import TTLCache, cached
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter

from lib.authentication import LDAPAuthentication
from lib.authorization import AuthorizationRule, AuthorizationRulesFile, AuthorizationRulesParser
from lib.bruteforce import BruteForce
from lib.logs import Logs


# --- Parameters --------------------------------------------------------------
AUTHORIZATION_INGRESS_RULES = getenv('AUTHORIZATION_INGRESS_RULES', 'disabled').lower()
PAGE_FOOTER = getenv('PAGE_FOOTER', '<small><a href="https://github.com/Argelbargel/external-ldap-auth" target="_blank">Powered by External LDAP Authentication</a></small>')

# --- Authentication & Authorization ------------------------------------------
defaultAuthRules = AuthorizationRulesFile(getenv("AUTHORIZATION_RULES_PATH", "./config/rules.conf"))
authCache = TTLCache(float('inf'), float(getenv("AUTH_CACHE_TTL_SECONDS", "15")))

# --- LDAP-Connection ---------------------------------------------------------
ldap = LDAPAuthentication(
        getenv('LDAP_ENDPOINT', ''), getenv('LDAP_BIND_DN'), 
        getenv('LDAP_SEARCH_BASE'), getenv('LDAP_SEARCH_FILTER'), 
        getenv('LDAP_MANAGER_DN'), getenv('LDAP_MANAGER_PASSWORD')
    )
bruteForce = BruteForce(
                getenv('BRUTE_FORCE_PROTECTION_ENABLED', "false").lower() == "true", 
                int(getenv('BRUTE_FORCE_MAX_FAILURE_COUNT', "5")), 
                int(getenv('BRUTE_FORCE_EXPIRATION_SECONDS', "60"))
            )

# --- Flask -------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(__name__)

# --- Metrics -------------------------------------------------------------------
metrics = PrometheusMetrics(app, group_by='endpoint', excluded_paths='^/(?!$)', default_latency_as_histogram=False)
blocked_ips = Counter('blocked_ips', 'IPs blocked by brute-force-protection', ['ip'])

# --- Logging -----------------------------------------------------------------
logs = Logs('main')

if AUTHORIZATION_INGRESS_RULES == "override":
    logs.warning(f"AUTHORIZATION_INGRESS_RULES is set to '{AUTHORIZATION_INGRESS_RULES}' - ingresses may completely override authorization required by default-rules!")
elif AUTHORIZATION_INGRESS_RULES == "append":
    logs.info(f"AUTHORIZATION_INGRESS_RULES is set to '{AUTHORIZATION_INGRESS_RULES}' - rules provided by ingresses only take effect if none of the default-rules apply.")
elif AUTHORIZATION_INGRESS_RULES != "disabled":
    logs.warning(f"Invalid value '{AUTHORIZATION_INGRESS_RULES}' for AUTHORIZATION_INGRESS_RULES provided!")
else:
    logs.info(f"AUTHORIZATION_INGRESS_RULES is set to '{AUTHORIZATION_INGRESS_RULES}' - rules provided by ingresses are ignored.")


def _request_host():
    return _parse_request_url().hostname

def _request_path():
    return _parse_request_url().path


# --- Routes ------------------------------------------------------------------
@app.route('/', methods=['GET'])
@metrics.counter('auth_requests', 'Authentication requests by hosts and status',
                 labels={'host': _request_host, 'status': lambda r: r.status_code})
def auth():
    ip = _request_ip()
    rule = _find_rule(_request_host(), ip, request.method, _request_path())
    headers = []

    if not rule.is_public():

        if not request.authorization:
            logs.debug('Missing authorization-header')
            return abort(401)

        username = request.authorization.username
        password = request.authorization.password

        if bruteForce.is_blocked(ip):
            logs.info('Rejecting request from blocked ip', ip=ip, username=username)
            return abort(429)

        authenticated, usergroups = _authenticate_(username, password)
        if not authenticated:
            logs.info('Authentication failed', ip=ip, username=username)

            if bruteForce.add_failure(ip):
                logs.warning('Blocking requests after to many authentication failures', ip=ip, username=username)
                blocked_ips.labels(ip=ip).inc()
                return abort(429)

            return abort(401)

        logs.debug('Authentication successful', ip=ip, username=username, groups=usergroups)

        authorized, matched_groups = rule.authorize(username, usergroups)
        if not authorized:
            logs.info('Authorization failed', ip=ip, username=username, host= _request_host(), rule=rule)
            return abort(403)

        headers=[('x-user', username),('x-groups', ",".join(matched_groups))]
        logs.debug('Authorization successful', ip=ip, username=username, host=_request_host(), groups=matched_groups, rule=rule)

    return _render_response(200, "Authorized", "You are authorized to access the requested resource", headers=headers)


@app.route('/health', methods=['GET'])
def health():
    if not ldap.health():
        return abort(503)
    return _render_response(200, "Healthy", "External LDAP Authentication is healthy")


@app.after_request
def global_headers(response):
    response.headers['Server'] = '' # Remove Server header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(HTTPException)
def handle_exception(e):
    if e.code not in [401, 403, 404, 405, 429]:
        logs.error('An error occurred while processing a request', ip=_request_ip(), path=request.path, code=e.code, name=e.name, description=e.description)

    return _render_response(e.code, e.name, e.description, "An Error Occurred While Processing Your Request")


@cached(authCache)
def _authenticate_(username, password):
    return ldap.authenticate(username, password)


@cached(authCache)
def _find_rule(host:str, ip:str, method:str, path:str) -> AuthorizationRule:
    rules = defaultAuthRules
    if AUTHORIZATION_INGRESS_RULES and 'AUTHORIZATION_RULES' in request.headers:
        customRules = AuthorizationRulesParser().parse(request.headers.get('AUTHORIZATION_RULES'))
        if AUTHORIZATION_INGRESS_RULES == "override":
            logs.debug("overriding default-rules with custom-rules", customRules=customRules, defaultRules=defaultAuthRules)
            rules = customRules.combine(defaultAuthRules)
        elif AUTHORIZATION_INGRESS_RULES == "append":
            logs.debug("appending custom-rules to default-rules", defaultRules=defaultAuthRules, customRules=customRules)
            rules = defaultAuthRules.combine(customRules)

    rule = rules.find_rule(host, ip, method, path)
    logs.info(f"Authenticating request using rule {rule}...", host=host, ip=ip, method=method, path=path)
    return rule


def _request_ip():
    # Nginx Ingress Controller returns the X-Forwarded-For in X-Original-Forwarded-For
    # The last IP from the list is the client IP
    if request.environ.get('HTTP_X_ORIGINAL_FORWARDED_FOR') is not None:
        nginxControllerIP = request.environ.get('HTTP_X_ORIGINAL_FORWARDED_FOR')
        nginxControllerIP = [x.strip() for x in nginxControllerIP.split(',')]
        return nginxControllerIP[-1]

    if request.environ.get('HTTP_X_REAL_IP') is not None:
        return request.environ.get('HTTP_X_REAL_IP')

    if request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
        return request.environ.get('HTTP_X_FORWARDED_FOR')

    return request.remote_addr


def _parse_request_url():
    url = request.url
    if request.environ.get('HTTP_X_ORIGINAL_URL') is not None:
        url = request.environ.get('HTTP_X_ORIGINAL_URL')
    return urlparse(url)


def _render_response(status_code, title, message, error = None, headers = None):
    if headers is None:
        headers = []

    layout = {
        'error': error,
        'title': title,
        'message': message,
        'footer': PAGE_FOOTER
    }

    if status_code == 401:
        headers.append( ('WWW-Authenticate', 'Basic realm=External LDAP Authentication'))

    return render_template('page.html', layout=layout), status_code, headers


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=True, use_reloader=True)
