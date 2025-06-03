import gunicorn
gunicorn.SERVER = 'External LDAP Authentication Service'
worker_class = 'gthread'
timeout = 30