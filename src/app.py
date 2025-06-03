from random import SystemRandom
from string import ascii_letters, digits

from flask import Flask
from flask import abort, request, render_template
from werkzeug.exceptions import HTTPException
from cachetools import TTLCache, cached
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter

from aldap.logs import Logs
from aldap.bruteforce import BruteForce
from aldap.parameters import Parameters
from aldap.aldap import Aldap



# --- Parameters --------------------------------------------------------------
param = Parameters()
PAGE_FOOTER = param.get('PAGE_FOOTER', '<small><a href="https://github.com/Argelbargel/external-ldap-auth" target="_blank">Powered by External LDAP Authentication</a></small>', str)

# --- LDAP-Connection ---------------------------------------------------------
ldap = Aldap(param.get('LDAP_ENDPOINT', default=''), param.get('LDAP_BIND_DN'), param.get('LDAP_SEARCH_BASE'), param.get('LDAP_SEARCH_FILTER'), param.get('LDAP_MANAGER_DN'), param.get('LDAP_MANAGER_PASSWORD'))
authCache = TTLCache(float('inf'), param.get("LDAP_AUTHENTICATION_CACHE_TTL_SECONDS", 15, float))

# --- Brute Force -------------------------------------------------------------
bruteForce = BruteForce(param.get('BRUTE_FORCE_PROTECTION_ENABLED', False, bool), param.get('BRUTE_FORCE_MAX_FAILURE_COUNT', 5, int), param.get('BRUTE_FORCE_EXPIRATION_SECONDS', 60, int))

# --- Logging -----------------------------------------------------------------
logs = Logs('main')

# --- Flask -------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(__name__)
app.config.update(SECRET_KEY=param.get('FLASK_SECRET_KEY', ''.join(SystemRandom().choice(ascii_letters + digits) for _ in range(16)), str))
metrics = PrometheusMetrics(app, group_by='endpoint', excluded_paths='^/(?!$)', default_latency_as_histogram=False)
blocked_ips = Counter('blocked_ips', 'IPs blocked by brute-force-protection', ['ip'])


# --- Routes ------------------------------------------------------------------
@app.route('/', methods=['GET'])
def auth():
    if not request.authorization:
        logs.debug({'message':'Missing authorization-header'})
        return abort(401)

    username = request.authorization.username
    password = request.authorization.password
    ip = _request_ip()

    if bruteForce.is_blocked(ip):
        logs.info({'message': 'Rejecting request from blocked ip', 'ip': ip, 'username': username})
        return abort(429)

    authenticated, usergroups = _authenticate_(username, password)
    if not authenticated:
        logs.info({'message': 'Authentication failed', 'ip': ip, 'username': username})

        if bruteForce.add_failure(ip):
            logs.warning({'message':'Blocking requests after to many authentication failures', 'ip': ip, 'username': username})
            blocked_ips.labels(ip=ip).inc()
            return abort(429)

        return abort(401)

    logs.debug({'message':'Authentication successful', 'ip': ip, 'username': username, 'groups': usergroups})

    allowed_users = param.get('LDAP_ALLOWED_USERS', default=None, type=str, only_env=False)
    allowed_groups = param.get('LDAP_ALLOWED_GROUPS', default=None, type=str, only_env=False)
    cond_groups = param.get('LDAP_CONDITIONAL_GROUPS', default='or', type=str, only_env=False).lower()
    cond_users_groups = param.get('LDAP_CONDITIONAL_USERS_GROUPS', default='or', type=str, only_env=False).lower()

    authorized, matched_groups = ldap.authorize(username, usergroups, allowed_users, allowed_groups, cond_groups, cond_users_groups)
    if not authorized:
        logs.info({'message': 'Authorization failed', 'ip': ip, 'username': username})
        return abort(403)

    logs.debug({'message':'Authorization successful', 'ip': ip, 'username': username, 'groups': matched_groups})
    return _render_response(200, "Authorized", "You are authorized to access the requested resource", headers=[('x-username', username),('x-groups', ",".join(matched_groups))])


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
        logs.error({'message': 'an error occurred while processing a request', 'ip': _request_ip(), 'path': request.path, 'code': e.code, 'name': e.name, 'description': e.description})

    return _render_response(e.code, e.name, e.description, "An Error Occurred While Processing Your Request") 


@cached(authCache)
def _authenticate_(username, password):
    return ldap.authenticate(username, password)


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


def _render_response(status_code, title, message, error = None, headers = None):
    if headers is None:
        headers = []

    layout = {
        'error': error,
        'realm': param.get('AUTH_REALM', 'LDAP Authentication', str, False),
        'title': title,
        'message': message,
        'footer': PAGE_FOOTER
    }

    if status_code == 401:
        headers.append( ('WWW-Authenticate', 'Basic realm=' + layout["realm"]))

    return render_template('page.html', layout=layout), status_code, headers


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=True, use_reloader=True)
