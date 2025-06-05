from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from db import init_db, get_db_connection, log_request
import requests
import jmespath
import json
import sqlite3
import logging

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-key'

# Initialize database schema and default SUPER user
init_db()

# Persistent requests.Session for storing cookies
http_session = requests.Session()


def _set_log_level():
    if app.debug:
        logger.setLevel(logging.DEBUG)

# Helper: check if user is logged in

def is_logged_in():
    return session.get('username') is not None

# ─── LOGIN / LOGOUT ROUTES ─────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        try:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ? AND password = ?',
                (username, password)
            ).fetchone()
            if user:
                gp_rows = conn.execute(
                    'SELECT gkey, gvalue FROM global_params WHERE user_id = ?',
                    (user['id'],)
                ).fetchall()
                conn.close()
                session['username'] = username
                gp_dict = {r['gkey']: r['gvalue'] for r in gp_rows}
                session['global_params'] = {
                    'initial': gp_dict,
                    'current': gp_dict.copy()
                }
                session.pop('results', None)
                logger.info('User %s logged in', username)
                return redirect(url_for('main'))
            logger.info('Invalid login for %s', username)
        except Exception:
            logger.exception('Login failed for %s', username)
            return render_template('login.html', error='Internal error'), 500
        finally:
            conn.close()
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    http_session.cookies.clear()
    logger.info('User logged out')
    return redirect(url_for('login'))

# ─── MAIN SPA ROUTE ─────────────────────────────────────────────────────────────

@app.route('/')
def main():
    if not is_logged_in():
        return redirect(url_for('login'))
    global_params = session.get('global_params', {'initial': {}, 'current': {}})
    logger.info('Rendering main page for %s', session.get('username'))
    return render_template('main.html', global_params=global_params)

# ─── AUTHENTICATE TO EXTERNAL ENDPOINT (CAPTURE COOKIE) ─────────────────────────

@app.route('/auth_toggle', methods=['POST'])
def auth_toggle():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    auth_url = request.form.get('auth_url', '')
    username = session['username']
    try:
        resp = http_session.get(auth_url, auth=(username, 'SUPER'))
        if resp.status_code == 200:
            logger.info('Auth toggle succeeded for %s', username)
            return jsonify({'status': 'success'})
        else:
            logger.error('Auth toggle failed for %s: %s', username, resp.text)
            return jsonify({'status': 'fail', 'message': resp.text}), 400
    except Exception:
        logger.exception('Auth toggle error for %s', username)
        return jsonify({'status': 'error', 'message': 'Internal error'}), 500

# ─── ENVIRONMENTS ROUTE ─────────────────────────────────────────────────────────

@app.route('/envs', methods=['GET', 'POST'])
def envs():
    if not is_logged_in():
        return redirect(url_for('login'))

    # Check if HTMX requested only the list
    list_only = request.args.get('list_only') == '1'
    conn = get_db_connection()
    try:
        # Handle POST to add/update environment; always return only envs_list.html
        if request.method == 'POST':
            data = request.form
            env_id = data.get('env_id')
            is_default = 1 if data.get('is_default') == 'on' else 0
            if env_id:
                if is_default:
                    conn.execute('UPDATE environments SET is_default=0')
                conn.execute(
                    'UPDATE environments SET name=?, base_url=?, port=?, default_headers=?, default_params=?, auth_settings=?, meta=?, tags=?, is_default=? WHERE id=?',
                    (
                        data['name'],
                        data['base_url'],
                        data.get('port'),
                        data.get('default_headers'),
                        data.get('default_params'),
                        data.get('auth_settings'),
                        data.get('meta'),
                        data.get('tags'),
                        is_default,
                        env_id
                    )
                )
            else:
                if is_default:
                    conn.execute('UPDATE environments SET is_default=0')
                conn.execute(
                    'INSERT INTO environments (name, base_url, port, default_headers, default_params, auth_settings, meta, tags, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        data['name'],
                        data['base_url'],
                        data.get('port'),
                        data.get('default_headers'),
                        data.get('default_params'),
                        data.get('auth_settings'),
                        data.get('meta'),
                        data.get('tags'),
                        is_default
                    )
                )
            conn.commit()

            envs = conn.execute('SELECT * FROM environments').fetchall()
            logger.info('Environment %s saved', data['name'])
            return render_template('envs_list.html', envs=envs)

        # GET request: fetch environments
        envs = conn.execute('SELECT * FROM environments').fetchall()
    except Exception:
        logger.exception('Error processing environments')
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    if list_only:
        return render_template('envs_list.html', envs=envs)

    global_params = session.get('global_params', {'initial': {}, 'current': {}})
    return render_template('envs.html', envs=envs, global_params=global_params)

@app.route('/delete_env/<int:env_id>', methods=['POST'])
def delete_env(env_id):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM environments WHERE id=?', (env_id,))
        conn.commit()
        envs = conn.execute('SELECT * FROM environments').fetchall()
        logger.info('Environment %s deleted', env_id)
    except Exception:
        logger.exception('Failed to delete environment %s', env_id)
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    return render_template('envs_list.html', envs=envs)

@app.route('/toggle_default/<int:env_id>', methods=['POST'])
def toggle_default(env_id):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        conn.execute('UPDATE environments SET is_default=0')
        conn.execute('UPDATE environments SET is_default=1 WHERE id=?', (env_id,))
        conn.commit()
        envs = conn.execute('SELECT * FROM environments').fetchall()
        logger.info('Environment %s set as default', env_id)
    except Exception:
        logger.exception('Failed to toggle default environment to %s', env_id)
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    return render_template('envs_list.html', envs=envs)

@app.route('/save_globals', methods=['POST'])
def save_globals():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 400
        uid = user['id']
        existing = {row['gkey'] for row in conn.execute('SELECT gkey FROM global_params WHERE user_id = ?', (uid,)).fetchall()}
        initial = {}
        for key, val in request.form.items():
            if key.startswith('gk_') and val.strip():
                idx = key.split('_')[1]
                gkey = val.strip()
                gvalue = request.form.get(f'gv_{idx}', '').strip()
                initial[gkey] = gvalue
                conn.execute(
                    'INSERT INTO global_params (user_id, gkey, gvalue) VALUES (?, ?, ?) '
                    'ON CONFLICT(user_id, gkey) DO UPDATE SET gvalue=excluded.gvalue',
                    (uid, gkey, gvalue)
                )
                existing.discard(gkey)
        for obsolete in existing:
            conn.execute('DELETE FROM global_params WHERE user_id = ? AND gkey = ?', (uid, obsolete))
        conn.commit()
        session['global_params'] = {'initial': initial, 'current': initial.copy()}
        logger.info('Global parameters saved for %s', session['username'])
    except Exception:
        logger.exception('Failed to save globals for %s', session.get('username'))
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    return jsonify({'status': 'success'})

@app.route('/delete_global/<gkey>', methods=['POST'])
def delete_global(gkey):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 400
        uid = user['id']
        conn.execute('DELETE FROM global_params WHERE user_id = ? AND gkey = ?', (uid, gkey))
        conn.commit()
        gp = session.get('global_params', {'initial': {}, 'current': {}})
        gp.get('initial', {}).pop(gkey, None)
        gp.get('current', {}).pop(gkey, None)
        session['global_params'] = gp
        logger.info('Global parameter %s deleted for %s', gkey, session['username'])
    except Exception:
        logger.exception('Failed to delete global %s for %s', gkey, session.get('username'))
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    return ('', 204)

# ─── COMMANDS & EXECUTION ROUTES ──────────────────────────────────────────────


@app.get('/commands')
def commands_page():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('commands_page.html')


@app.get('/commands/list')
def list_commands():
    """Return list of commands, optionally filtered by a search term."""
    if not is_logged_in():
        return redirect(url_for('login'))

    search = request.args.get('search', '').strip()
    conn = get_db_connection()
    try:
        if search:
            like = f"%{search}%"
            cmds = conn.execute(
                "SELECT * FROM commands WHERE name LIKE ? ORDER BY name",
                (like,)
            ).fetchall()
        else:
            cmds = conn.execute(
                "SELECT * FROM commands ORDER BY name"
            ).fetchall()
    except Exception:
        logger.exception('Failed to fetch commands list')
        conn.close()
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()

    return render_template('commands_list.html', commands=cmds)


@app.get('/commands/dropdown')
def commands_dropdown():
    """Return the search + list partial for commands."""
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('commands_dropdown.html')


@app.get('/commands/form')
def command_form():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('commands_form.html')

@app.post('/commands')
def save_command():
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = get_db_connection()
    error_msg = None
    try:
        data = request.form
        headers_json = json.dumps([
            {'key': k, 'value': v}
            for k, v in zip(request.form.getlist('header_key'), request.form.getlist('header_val'))
            if k
        ])
        params_json = json.dumps([
            {'key': k, 'value': v}
            for k, v in zip(request.form.getlist('param_key'), request.form.getlist('param_val'))
            if k
        ])
        try:
            conn.execute(
                'INSERT INTO commands (name, http_method, endpoint, headers, params, auth_type, body_template, extract_rule, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    data['name'], data['http_method'], data['endpoint'],
                    headers_json, params_json,
                    data.get('auth_type'), data.get('body_template'),
                    data.get('extract_rule'), data.get('notes')
                )
            )
            conn.commit()
            logger.info('Command %s saved', data['name'])
            if app.debug:
                logger.debug('Inserted command data: %s', dict(data))
        except sqlite3.IntegrityError:
            error_msg = 'A command with that name already exists.'
    except Exception:
        logger.exception('Error saving command')
        conn.close()
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    return render_template('commands_form.html', error_msg=error_msg)

@app.route('/delete_command/<int:cmd_id>', methods=['POST'])
def delete_command(cmd_id):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM commands WHERE id=?', (cmd_id,))
        conn.commit()
        logger.info('Command %s deleted', cmd_id)
    except Exception:
        logger.exception('Failed to delete command %s', cmd_id)
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()

    if request.headers.get('HX-Request'):
        conn = get_db_connection()
        cmds = conn.execute('SELECT * FROM commands ORDER BY name').fetchall()
        conn.close()
        return render_template('commands_list.html', commands=cmds)
    return redirect(url_for('commands_page'))



@app.route('/execute', methods=['POST'])
def execute_script():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    script = request.form['script']
    lines = [line.strip() for line in script.splitlines() if line.strip()]
    gp = session.get('global_params', {'initial': {}, 'current': {}})
    stack_vars = gp.get('current', {}).copy()
    log_entries = []
    results = []
    conn = get_db_connection()
    try:
        env = (conn.execute('SELECT * FROM environments WHERE is_default=1 LIMIT 1').fetchone()
             or conn.execute('SELECT * FROM environments LIMIT 1').fetchone())
    except Exception:
        logger.exception('Failed fetching environment')
        conn.close()
        return jsonify({'error': 'Internal error'}), 500
    finally:
        conn.close()
    base = ''
    if env:
        base = env['base_url'] + (f":{env['port']}" if env['port'] else '')
    for line in lines:
        if line.lower().startswith('catch'):
            continue
        cmd_name = line
        conn = get_db_connection()
        try:
            cmd = conn.execute('SELECT * FROM commands WHERE name = ?', (cmd_name,)).fetchone()
        except Exception:
            conn.close()
            logger.exception('Failed to fetch command %s', cmd_name)
            log_entries.append({'type': 'error', 'message': f'Command lookup failed: {cmd_name}'})
            break
        finally:
            conn.close()
        if not cmd:
            log_entries.append({'type': 'error', 'message': f'Command not found: {cmd_name}'})
            break
        url = base.rstrip('/') + '/' + cmd['endpoint'].lstrip('/') if base else cmd['endpoint']
        headers_list = json.loads(cmd['headers'] or '[]')
        headers = {h['key']: h['value'] for h in headers_list}
        params_list = json.loads(cmd['params'] or '[]')
        params = {p['key']: p['value'] for p in params_list}
        body = cmd['body_template'] or ''
        for var, val in stack_vars.items():
            placeholder = f'{{{{{var}}}}}'
            url = url.replace(placeholder, val)
            body = body.replace(placeholder, val)
            headers = {k: v.replace(placeholder, val) for k, v in headers.items()}
            params = {k: v.replace(placeholder, val) for k, v in params.items()}
        log_entries.append({
            'type': 'info',
            'message': f"REQUEST {cmd_name}: {cmd['http_method']} {url}\nHeaders: {json.dumps(headers)}\nParams: {json.dumps(params)}\nBody: {body}"
        })
        try:
            resp = http_session.request(cmd['http_method'], url, headers=headers, params=params, data=body)
            status = resp.status_code
            log_request(cmd['http_method'], url, body, status, resp.text)
            try:
                resp_json = resp.json()
            except ValueError:
                resp_json = {'raw': resp.text}
            log_entries.append({
                'type': 'info',
                'message': f"RESPONSE {cmd_name}: {status}\n{json.dumps(resp_json, indent=2)}"
            })
            results.append({'command': cmd_name, 'response': resp_json})
            if cmd['extract_rule'] and isinstance(resp_json, (dict, list)):
                extracted = jmespath.search(cmd['extract_rule'], resp_json)
                if extracted is not None:
                    var_name = cmd['extract_rule'].split('.')[-1]
                    stack_vars[var_name] = str(extracted)
                    gp['current'][var_name] = str(extracted)
                    session['global_params'] = gp
        except Exception as e:
            logger.exception('%s execution failed', cmd_name)
            log_entries.append({'type': 'error', 'message': f'{cmd_name} exception: {str(e)}'})
            break
    session['results'] = results
    return render_template('logs.html', logs=log_entries)

@app.route('/results', methods=['GET'])
def get_results():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify(session.get('results', []))


@app.route('/request_logs')
def view_request_logs():
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM request_logs ORDER BY ts DESC').fetchall()
    conn.close()
    return render_template('request_logs.html', logs=logs)

if __name__ == '__main__':
    app.config['DEBUG'] = True
    _set_log_level()
    app.run(debug=True)
