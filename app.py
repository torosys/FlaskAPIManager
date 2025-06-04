from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from db import init_db, get_db_connection
import requests
import jmespath
import json
import sqlite3

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-key'

# Initialize database schema and default SUPER user
init_db()

# Persistent requests.Session for storing cookies
http_session = requests.Session()

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
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, password)
        ).fetchone()
        conn.close()
        if user:
            session['username'] = username
            session.pop('global_params', None)
            session.pop('results', None)
            return redirect(url_for('main'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    http_session.cookies.clear()
    return redirect(url_for('login'))

# ─── MAIN SPA ROUTE ─────────────────────────────────────────────────────────────

@app.route('/')
def main():
    if not is_logged_in():
        return redirect(url_for('login'))
    global_params = session.get('global_params', {'initial': {}, 'current': {}})
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
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'fail', 'message': resp.text}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ─── ENVIRONMENTS ROUTE ─────────────────────────────────────────────────────────

@app.route('/envs', methods=['GET', 'POST'])
def envs():
    if not is_logged_in():
        return redirect(url_for('login'))

    # Check if HTMX requested only the list
    list_only = request.args.get('list_only') == '1'
    conn = get_db_connection()

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
        conn.close()
        return render_template('envs_list.html', envs=envs)

    # GET request: fetch environments
    envs = conn.execute('SELECT * FROM environments').fetchall()
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
    conn.execute('DELETE FROM environments WHERE id=?', (env_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/toggle_default/<int:env_id>', methods=['POST'])
def toggle_default(env_id):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    conn.execute('UPDATE environments SET is_default=0')
    conn.execute('UPDATE environments SET is_default=1 WHERE id=?', (env_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/save_globals', methods=['POST'])
def save_globals():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    initial = {}
    for key, val in request.form.items():
        if key.startswith('gk_') and val.strip():
            idx = key.split('_')[1]
            initial[val.strip()] = request.form.get(f'gv_{idx}', '').strip()
    session['global_params'] = {'initial': initial, 'current': initial.copy()}
    return jsonify({'status': 'success'})

# ─── COMMANDS & EXECUTION ROUTES (UNCHANGED) ───────────────────────────────────

@app.route('/commands', methods=['GET', 'POST'])
def commands():
    if not is_logged_in():
        return redirect(url_for('login'))
    list_only = request.args.get('list_only') == '1'
    form_only = request.args.get('form_only') == '1'
    conn = get_db_connection()
    error_msg = None
    if request.method == 'POST':
        data = request.form
        cmd_id = data.get('cmd_id')
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
            if cmd_id:
                conn.execute(
                    'UPDATE commands SET name=?, http_method=?, endpoint=?, headers=?, params=?, auth_type=?, body_template=?, extract_rule=?, notes=? WHERE id=?',
                    (
                        data['name'], data['http_method'], data['endpoint'],
                        headers_json, params_json,
                        data.get('auth_type'), data.get('body_template'),
                        data.get('extract_rule'), data.get('notes'),
                        cmd_id
                    )
                )
            else:
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
        except sqlite3.IntegrityError:
            error_msg = 'A command with that name already exists.'
    cmds = conn.execute('SELECT * FROM commands').fetchall()
    conn.close()
    if list_only:
        return render_template('commands_list.html', commands=cmds)
    if form_only:
        return render_template('commands_form.html', commands=cmds, error_msg=error_msg)
    return render_template('commands.html', commands=cmds, error_msg=error_msg)

@app.route('/delete_command/<int:cmd_id>', methods=['POST'])
def delete_command(cmd_id):
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db_connection()
    conn.execute('DELETE FROM commands WHERE id=?', (cmd_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('commands'))

@app.route('/edit_command/<int:cmd_id>', methods=['GET'])
def edit_command(cmd_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = get_db_connection()
    cmd = conn.execute('SELECT * FROM commands WHERE id = ?', (cmd_id,)).fetchone()
    conn.close()
    if not cmd:
        return redirect(url_for('commands'))
    headers_list = json.loads(cmd['headers'] or '[]')
    params_list = json.loads(cmd['params'] or '[]')
    return render_template('edit_command.html', cmd=cmd, headers=headers_list, params=params_list)

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
    env = (conn.execute('SELECT * FROM environments WHERE is_default=1 LIMIT 1').fetchone()
         or conn.execute('SELECT * FROM environments LIMIT 1').fetchone())
    conn.close()
    base = ''
    if env:
        base = env['base_url'] + (f":{env['port']}" if env['port'] else '')
    for line in lines:
        if line.lower().startswith('catch'):
            continue
        cmd_name = line
        conn = get_db_connection()
        cmd = conn.execute('SELECT * FROM commands WHERE name = ?', (cmd_name,)).fetchone()
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
        try:
            resp = http_session.request(cmd['http_method'], url, headers=headers, params=params, data=body)
            status = resp.status_code
            log_entries.append({'type': 'info', 'message': f'{cmd_name}: {status}'})
            try:
                resp_json = resp.json()
            except:
                resp_json = {'raw': resp.text}
            results.append({'command': cmd_name, 'response': resp_json})
            if cmd['extract_rule']:
                data_json = resp.json()
                extracted = jmespath.search(cmd['extract_rule'], data_json)
                if extracted is not None:
                    var_name = cmd['extract_rule'].split('.')[-1]
                    stack_vars[var_name] = str(extracted)
                    gp['current'][var_name] = str(extracted)
                    session['global_params'] = gp
        except Exception as e:
            log_entries.append({'type': 'error', 'message': f'{cmd_name} exception: {str(e)}'})
            break
    session['results'] = results
    return jsonify({'logs': log_entries, 'results': results})

@app.route('/results', methods=['GET'])
def get_results():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify(session.get('results', []))

if __name__ == '__main__':
    app.run(debug=True)