from flask import Flask
from flask import abort, request, render_template
from werkzeug.exceptions import HTTPException
from aldap.logs import Logs
from aldap.bruteforce import BruteForce
from aldap.parameters import Parameters
from aldap.aldap import Aldap
from random import SystemRandom
from string import ascii_letters, digits
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter

# --- Parameters --------------------------------------------------------------
param = Parameters()
PAGE_FOOTER = param.get('PAGE_FOOTER', '<small><a href="https://github.com/Argelbargel/external-ldap-auth" target="_blank">Powered by External LDAP Authentication</a></small>', str)

# --- LDAP-Connection ---------------------------------------------------------
ldap = Aldap(param.get('LDAP_ENDPOINT', default=''), param.get('LDAP_BIND_DN'), param.get('LDAP_SEARCH_BASE'), param.get('LDAP_SEARCH_FILTER'), param.get('LDAP_MANAGER_DN'), param.get('LDAP_MANAGER_PASSWORD'))

# --- Brute Force -------------------------------------------------------------
bruteForce = BruteForce(param.get('BRUTE_FORCE_PROTECTION_ENABLED', False, bool), param.get('BRUTE_FORCE_MAX_FAILURE_COUNT', 5, int), param.get('BRUTE_FORCE_EXPIRATION_SECONDS', 60, int))

# --- Logging -----------------------------------------------------------------
logs = Logs('main')

# --- Flask -------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=param.get('FLASK_SECRET_KEY', ''.join(SystemRandom().choice(ascii_letters + digits) for _ in range(16)), str)
)
metrics = PrometheusMetrics(app, export_defaults=False)
authentication_failures = Counter('authentication_failures', 'Failed authentication requests', ['username'])
authorization_failures = Counter('authorization_failures', 'Failed authorization requests', ['username', 'groups', 'users'])
blocked_ips = Counter('blocked_ips', 'IPs blocked by bruteforce-protection', ['ip'])
app.config.from_object(__name__)


# --- Routes ------------------------------------------------------------------
@app.route('/', methods=['GET'])
@metrics.counter('auth_requests', 'Number of auth requests')
def auth():
    if bruteForce.isIpBlocked():
        return abort(429)

    username = None
    password = None

    if not request.authorization:
        logs.debug({'message':'missing authorization-header'})
        return abort(401)

    logs.debug({'message':'/basic-auth: authentication requested.'})
    username = request.authorization.username
    password = request.authorization.password

    if not ldap.authenticate(username, password):
        logs.warning({'message': 'Authentication failed', 'username': username})
        authentication_failures.labels(username=username).inc()
        if bruteForce.addRequest():
            blocked_ips.labels(ip=bruteForce.getRequestIP()).inc()
        return abort(401)


    allowed_users = param.get('LDAP_ALLOWED_USERS', default=None, type=str, onlyEnv=False)
    allowed_groups = param.get('LDAP_ALLOWED_GROUPS', default=None, type=str, onlyEnv=False)
    cond_groups = param.get('LDAP_CONDITIONAL_GROUPS', default='or', type=str, onlyEnv=False).lower()
    cond_users_groups = param.get('LDAP_CONDITIONAL_USERS_GROUPS', default='or', type=str, onlyEnv=False).lower()
    authorization, matchedGroups = ldap.authorize(username, allowed_users, allowed_groups, cond_groups, cond_users_groups)
    if not authorization:
        logs.warning({'message': 'Authorization failed', 'username': username})
        authorization_failures.labels(username=username, groups=allowed_groups, users=allowed_users).inc()
        return abort(403)

    logs.debug({'message':'Authorization successful', 'username': username, 'groups': matchedGroups})
    return render_response(200, "Authorized", "You are authorized to access the requested resource", headers=[('x-username', username),('x-groups', ",".join(matchedGroups))])

@app.route('/health', methods=['GET'])
def health():
    if not ldap.health():
        return abort(503)
    return render_response(200, "Healthy", "External LDAP Authentication is healthy")



@app.after_request
def afterAll(response):
    response.headers['Server'] = '' # Remove Server header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(HTTPException)
def handle_exception(e):
    if e.code not in [401, 403, 404, 405, 429]:
        logs.error({'message': 'an error occurred while processing a request', 'path': request.path, 'code': e.code, 'name': e.name, 'description': e.description})

    return render_response(e.code, e.name, e.description, "An Error Occurred While Processing Your Request") 


def render_response(status_code, title, message, error = None, headers = []):
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