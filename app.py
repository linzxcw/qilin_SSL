import os
import subprocess
import ssl
import datetime
import json
import shutil
import stat
import time
import http.server
import socketserver
import threading
import socket
from functools import wraps
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, session, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote

app = Flask(__name__)
app.config['CA_DIR'] = 'ca'
app.config['CERTS_DIR'] = 'certs'
app.config['UPLOAD_DIR'] = 'uploads'
app.config['BASE_DIR'] = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.urandom(24)  # 用于session加密

# 从JSON文件加载用户数据
def load_users():
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # 如果文件不存在，创建默认用户
        default_users = {
            'admin': {
                'password': generate_password_hash('admin123'),
                'role': 'admin'
            }
        }
        save_users(default_users)
        return default_users

def save_users(users):
    users_file = os.path.join(app.config['BASE_DIR'], 'users.json')
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

# 初始化用户数据
USERS = load_users()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            session['username'] = username
            response = make_response(redirect(url_for('index')))
            
            if remember:  # 如果选择了"记住我"，设置30天的cookie
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(days=30)
            
            return response
        
        return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        # 验证原密码
        if not check_password_hash(USERS[session['username']]['password'], old_password):
            return render_template('settings.html', username=session['username'], error='原密码错误')
        
        # 更新用户名和密码
        old_username = session['username']
        USERS[username] = USERS.pop(old_username)  # 更新用户名（键值）
        USERS[username]['password'] = generate_password_hash(new_password)  # 更新密码
        save_users(USERS)  # 保存更新后的用户信息到文件
        session['username'] = username  # 更新session中的用户名
        return render_template('settings.html', username=username, success='用户信息更新成功')
    
    return render_template('settings.html', username=session['username'])

# 初始化目录
os.makedirs(app.config['CA_DIR'], exist_ok=True)
os.makedirs(app.config['CERTS_DIR'], exist_ok=True)
os.makedirs(app.config['UPLOAD_DIR'], exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有文件被上传'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_DIR'], filename)
        file.save(file_path)
        return jsonify({'success': True, 'filename': filename})

def generate_ca(org_name=None, password=None):
    # 使用相对路径
    ca_dir = app.config['CA_DIR']
    ca_key = os.path.join(ca_dir, 'qilin-ca.key')
    ca_crt = os.path.join(ca_dir, 'qilin-ca.crt')
    ca_info_file = os.path.join(ca_dir, 'ca_info.json')
    
    print(f"CA目录: {ca_dir}")
    print(f"CA密钥路径: {ca_key}")
    print(f"CA证书路径: {ca_crt}")
    
    # 确保CA目录存在
    os.makedirs(ca_dir, exist_ok=True)
    
    # 如果没有提供机构名称，使用默认值
    if not org_name:
        org_name = "qilin SSL CA"
    
    try:
        # 使用本地OpenSSL
        openssl_cmd = os.path.join('bin', 'openssl.exe')
        if not os.path.exists(openssl_cmd):
            raise Exception("本地OpenSSL工具不可用，请确保bin目录下存在openssl.exe")
        print(f"使用本地OpenSSL: {openssl_cmd}")
        config_param = []
        
        # 生成 CA 私钥
        print("开始生成CA私钥...")
        if password:
            # 使用密码保护私钥
            key_cmd = [
                openssl_cmd, 'genrsa', '-des3', '-passout', f'pass:{password}',
                '-out', ca_key, '4096'
            ]
            result = subprocess.run(key_cmd, capture_output=True, text=True, check=True)
            print(f"私钥生成结果: {result.stdout}")
        else:
            # 不使用密码
            key_cmd = [
                openssl_cmd, 'genrsa', '-out', ca_key, '4096'
            ]
            result = subprocess.run(key_cmd, capture_output=True, text=True, check=True)
            print(f"私钥生成结果: {result.stdout}")

        # 检查私钥文件是否生成
        if not os.path.exists(ca_key):
            raise Exception(f"CA私钥文件未生成: {ca_key}")
        else:
            print(f"CA私钥文件已生成: {ca_key}")

        # 生成 CA 根证书
        print("开始生成CA根证书...")
        req_cmd = [
            openssl_cmd, 'req', '-config', 'bin/cnf/openssl.cnf', '-x509', '-new', '-nodes',
            '-key', ca_key, '-sha256', '-days', '3650',
            '-out', ca_crt,
            '-subj', f'/C=CN/ST=Guangdong/L=Shenzhen/O={org_name}/OU=Certificate Authority Department/CN={org_name}/emailAddress=ca@qilin-ssl.com'
        ]
        
        # 如果设置了密码，添加密码参数
        if password:
            req_cmd.extend(['-passin', f'pass:{password}'])
        
        print(f"执行命令: {' '.join(req_cmd)}")
        result = subprocess.run(req_cmd, capture_output=True, text=True, check=True)
        print(f"证书生成结果: {result.stdout}")
        
        # 检查证书文件是否生成
        if not os.path.exists(ca_crt):
            raise Exception(f"CA证书文件未生成: {ca_crt}")
        else:
            print(f"CA证书文件已生成: {ca_crt}")
        
        # 保存CA证书信息
        ca_info = {
            'org_name': org_name,
            'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'valid_until': (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d'),
            'has_password': bool(password)
        }
        
        with open(ca_info_file, 'w', encoding='utf-8') as f:
            json.dump(ca_info, f, ensure_ascii=False)
        
        print(f"CA信息文件已保存: {ca_info_file}")
        return ca_key, ca_crt, ca_info
    
    except subprocess.CalledProcessError as e:
        error_msg = f"执行OpenSSL命令失败: {str(e)}"
        if e.stderr:
            error_msg += f"\n错误输出: {e.stderr}"
        print(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        print(f"生成CA证书时出错: {str(e)}")
        raise

@app.route('/')
@login_required
def index():
    # 检查是否存在CA证书信息
    ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
    ca_info = None
    
    if os.path.exists(ca_info_file):
        with open(ca_info_file, 'r', encoding='utf-8') as f:
            ca_info = json.load(f)
    
    return render_template('index.html', ca_info=ca_info)

@app.route('/verify')
@login_required
def verify():
    return render_template('verify.html')

@app.route('/proxy')
@login_required
def proxy():
    return render_template('proxy.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/create_ca', methods=['POST'])
def create_ca():
    # 获取用户输入
    org_name = request.form.get('org_name', '')
    password = request.form.get('password', '')
    
    # 如果org_name为空，使用默认值
    if not org_name:
        org_name = "qilin SSL CA"
    
    # 如果password为空，则不使用密码
    if not password:
        password = None
    
    try:
        # 删除现有的CA证书（如果存在）
        ca_dir = os.path.abspath(app.config['CA_DIR'])
        ca_key = os.path.join(ca_dir, 'qilin-ca.key')
        ca_crt = os.path.join(ca_dir, 'qilin-ca.crt')
        ca_info_file = os.path.join(ca_dir, 'ca_info.json')
        
        print(f"准备删除现有CA证书文件（如果存在）")
        for file in [ca_key, ca_crt, ca_info_file]:
            try:
                if os.path.exists(file):
                    os.remove(file)
                    print(f"已删除文件: {file}")
            except Exception as file_error:
                print(f"删除文件失败: {file}, 错误: {str(file_error)}")
                return f"删除现有CA证书文件失败: {str(file_error)}", 500
        
        # 生成新的CA证书
        print("开始生成新的CA证书...")
        try:
            _, _, ca_info = generate_ca(org_name, password)
            print("CA证书生成成功")
        except Exception as gen_error:
            print(f"生成CA证书失败: {str(gen_error)}")
            return f"生成CA证书失败: {str(gen_error)}", 500
        
        # 生成表格HTML
        html = f'''
        <tr>
            <td>{ca_info['org_name']}</td>
            <td>{ca_info['valid_until']}</td>
            <td>{ca_info['created_at']}</td>
            <td><a href="{url_for('download', cert_dir='ca', filename='qilin-ca.crt')}"><i class="fas fa-download"></i> 下载CA证书</a></td>
        </tr>
        '''
        
        return html
    except Exception as e:
        print(f"创建CA证书时出现未捕获的错误: {str(e)}")
        return str(e), 500

@app.route('/delete_ca', methods=['POST'])
def delete_ca():
    try:
        # 删除CA证书文件
        ca_key = os.path.join(app.config['CA_DIR'], 'qilin-ca.key')
        ca_crt = os.path.join(app.config['CA_DIR'], 'qilin-ca.crt')
        ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
        ca_srl = os.path.join(app.config['CA_DIR'], 'qilin-ca.srl')
        
        deleted_files = []
        errors = []
        
        for file in [ca_key, ca_crt, ca_info_file, ca_srl]:
            try:
                if os.path.exists(file):
                    os.remove(file)
                    deleted_files.append(os.path.basename(file))
            except Exception as file_error:
                errors.append(f"删除{os.path.basename(file)}失败: {str(file_error)}")
        
        if errors:
            print(f"删除CA证书时出现错误: {', '.join(errors)}")
            return f"删除文件时出现错误: {', '.join(errors)}", 500
        
        if deleted_files:
            print(f"成功删除文件: {', '.join(deleted_files)}")
        else:
            print("没有找到需要删除的文件")
        
        # 返回空表格行
        return '<tr class="empty-row"><td colspan="4">证书申请前需要创建虚拟机构，请点击左上角按钮创建</td></tr>'
    except Exception as e:
        print(f"删除CA证书时出现未知错误: {str(e)}")
        return str(e), 500

@app.route('/create_cert', methods=['POST'])
def create_cert():
    # 获取用户输入
    cert_name = request.form.get('cert_name', '')
    ip_addresses = request.form.get('ip_addresses', '')
    domains = request.form.get('domains', '')
    password = request.form.get('cert_password', '')
    
    if not cert_name:
        return "证书名称不能为空", 400
    
    # 检查CA证书是否存在
    ca_key = os.path.join(app.config['CA_DIR'], 'qilin-ca.key')
    ca_crt = os.path.join(app.config['CA_DIR'], 'qilin-ca.crt')
    ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
    
    if not (os.path.exists(ca_key) and os.path.exists(ca_crt) and os.path.exists(ca_info_file)):
        return "请先创建虚拟机构，后申请证书", 400
    
    try:
        # 使用本地OpenSSL
        openssl_cmd = os.path.join('bin', 'openssl.exe')
        if not os.path.exists(openssl_cmd):
            return "本地OpenSSL工具不可用，请确保bin目录下存在openssl.exe", 400
        print(f"使用本地OpenSSL: {openssl_cmd}")
        config_param = []
        
        # 生成唯一目录
        cert_dir = os.path.join(app.config['CERTS_DIR'], cert_name)
        os.makedirs(cert_dir, exist_ok=True)

        # 生成服务器证书文件名
        key_file = os.path.join(cert_dir, f'{cert_name}.key')
        csr_file = os.path.join(cert_dir, f'{cert_name}.csr')
        crt_file = os.path.join(cert_dir, f'{cert_name}.crt')
        ext_file = os.path.join(cert_dir, f'{cert_name}.ext')

        # 生成私钥
        key_cmd = [openssl_cmd, 'genrsa', '-out', key_file, '2048']
        # 不再使用配置文件参数
        subprocess.run(key_cmd, check=True)

        # 生成 CSR
        csr_cmd = [openssl_cmd, 'req', '-new', '-key', key_file,
                  '-out', csr_file,
                  '-config', 'bin/cnf/openssl.cnf',
                  '-subj', f'/C=CN/ST=Guangdong/L=Shenzhen/O=qilin SSL CA/OU=IT Department/CN={cert_name}']
        subprocess.run(csr_cmd, check=True)
        # 构建SAN扩展内容
        san_entries = []
        
        # 处理IP地址
        if ip_addresses:
            for ip in ip_addresses.split(';'):
                ip = ip.strip()
                if ip:
                    san_entries.append(f'IP:{ip}')
        
        # 处理域名
        if domains:
            for domain in domains.split(';'):
                domain = domain.strip()
                if domain:
                    san_entries.append(f'DNS:{domain}')
        
        # 如果没有指定任何SAN，至少添加证书名称作为DNS
        if not san_entries:
            san_entries.append(f'DNS:{cert_name}')
        
        san_string = ', '.join(san_entries)

        # 创建扩展文件
        with open(ext_file, 'w') as f:
            f.write(f"""[req]
req_extensions = v3_req

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = {san_string}""")

        # 签发证书
        ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
        ca_key = os.path.join(app.config['CA_DIR'], 'qilin-ca.key')
        ca_crt = os.path.join(app.config['CA_DIR'], 'qilin-ca.crt')
        
        # 读取CA信息以获取密码状态
        if os.path.exists(ca_info_file):
            with open(ca_info_file, 'r', encoding='utf-8') as f:
                ca_info = json.load(f)
                has_password = ca_info.get('has_password', False)
        else:
            has_password = False
        
        # 构建签名命令
        sign_cmd = [
            openssl_cmd, 'x509', '-req', '-in', csr_file,
            '-CA', ca_crt, '-CAkey', ca_key,
            '-CAcreateserial', '-out', crt_file,
            '-days', '3650', '-extfile', ext_file, '-extensions', 'v3_req'
        ]
        
        
        # 如果CA密钥有密码保护，添加密码参数
        if has_password and password:
            sign_cmd.extend(['-passin', f'pass:{password}'])
        elif has_password and not password:
            return "CA证书有密码保护，请提供密码", 400
        
        # 执行签名命令，添加超时机制
        try:
            # 使用subprocess.Popen和communicate替代run，以便添加超时
            process = subprocess.Popen(sign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=10)  # 设置10秒超时
            
            # 检查命令执行结果
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                # 检查是否是密码错误
                if "bad decrypt" in error_msg or "bad password" in error_msg:
                    return "CA证书密码错误，请重试", 400
                else:
                    return f"证书签发失败: {error_msg}", 500
        except subprocess.TimeoutExpired:
            # 如果超时，终止进程并返回错误
            process.kill()
            return "证书签发超时，可能是密码错误导致进程等待输入", 500
        
        # 计算证书有效期
        valid_until = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
    
        # 处理IP地址显示，转换为HTML列表格式
        if ip_addresses:
            ip_list = ip_addresses.split('\n')
            has_more_ip = len(ip_list) > 3
            ip_html = '<ul class="address-list' + (' has-more' if has_more_ip else '') + '">' 
            for ip in ip_list:  # 显示所有IP地址
                ip_html += f'<li>{ip}</li>'
            ip_html += '</ul>'
            display_ip = ip_html
        else:
            display_ip = '/'
        
        # 处理域名显示，转换为HTML列表格式
        if domains:
            domain_list = domains.split('\n')
            has_more_domain = len(domain_list) > 3
            domain_html = '<ul class="address-list' + (' has-more' if has_more_domain else '') + '">' 
            for domain in domain_list:  # 显示所有域名
                domain_html += f'<li>{domain}</li>'
            domain_html += '</ul>'
            display_domains = domain_html
        else:
            display_domains = '/'
        
        # 生成表格HTML
        html = f'''
    <tr>
        <td><input type="checkbox" class="cert-checkbox" data-cert-name="{cert_name}"></td>
        <td>{cert_name}</td>
        <td>{valid_until}</td>
        <td title="{ip_addresses.replace('/', ', ') if ip_addresses else '/'}" class="ip-address">{display_ip}</td>
        <td title="{domains.replace('/', ', ') if domains else '/'}" class="domain-name">{display_domains}</td>
        <td><a href="{url_for('download', cert_dir=cert_dir, filename=f'{cert_name}.crt')}"><i class="fas fa-certificate"></i> {cert_name}.crt</a></td>
        <td><a href="{url_for('download', cert_dir=cert_dir, filename=f'{cert_name}.key')}"><i class="fas fa-key"></i> {cert_name}.key</a></td>
    </tr>
    '''
        
        return html
    except Exception as e:
        return str(e), 500

@app.route('/download/<path:cert_dir>/<filename>')
def download(cert_dir, filename):
    # 检查cert_dir是否是相对路径，如果是，则拼接CERTS_DIR
    if not os.path.isabs(cert_dir):
        if cert_dir == 'ca':
            # 如果是CA证书目录
            full_path = os.path.join(app.config['CA_DIR'], filename)
        else:
            # 如果是普通证书目录
            full_path = os.path.join(app.config['CERTS_DIR'], cert_dir, filename)
    else:
        full_path = os.path.join(cert_dir, filename)
    
    # 检查文件是否存在
    if not os.path.exists(full_path):
        return f"文件不存在: {full_path}", 404
        
    return send_file(full_path, as_attachment=True)

@app.route('/start_https_server/<path:cert_dir>')
def start_https_server(cert_dir):
    # 获取证书和私钥路径
    server_crt = os.path.join(cert_dir, 'server.crt')
    server_key = os.path.join(cert_dir, 'server.key')
    
    # 设置全局变量，用于在主程序中启动HTTPS服务器
    app.config['HTTPS_SERVER_ENABLED'] = True
    app.config['HTTPS_SERVER_CERT'] = server_crt
    app.config['HTTPS_SERVER_KEY'] = server_key
    
    return redirect(url_for('index', https_started=True))

@app.route('/https_test')
def https_test():
    return "<h1>HTTPS服务器测试成功！</h1><p>您已成功使用生成的SSL证书建立了安全连接。</p>"

@app.route('/verify_cert', methods=['POST'])
def verify_cert():
    """验证证书按钮的路由处理函数"""
    try:
        # 获取用户输入的IP地址或域名
        address = request.form.get('address', '')
        cert_type = request.form.get('cert_type', 'qilin')
        
        if not address:
            return jsonify({'success': False, 'message': '请输入IP地址或域名'}), 400
        
        # 确定证书和私钥文件路径
        if cert_type == 'qilin':
            # 使用qilin SSL申请的证书
            cert_name = request.form.get('cert_name', '')
            if not cert_name:
                return jsonify({'success': False, 'message': '请选择证书'}), 400
                
            cert_dir = os.path.join(app.config['CERTS_DIR'], cert_name)
            cert_file = os.path.join(cert_dir, f'{cert_name}.crt')
            key_file = os.path.join(cert_dir, f'{cert_name}.key')
            
            if not (os.path.exists(cert_file) and os.path.exists(key_file)):
                return jsonify({'success': False, 'message': '证书文件不存在'}), 404
        else:
            # 使用上传的自定义证书
            cert_filename = request.form.get('cert_filename', '')
            key_filename = request.form.get('key_filename', '')
            
            if not cert_filename or not key_filename:
                return jsonify({'success': False, 'message': '请上传证书和私钥文件'}), 400
                
            cert_file = os.path.join(app.config['UPLOAD_DIR'], cert_filename)
            key_file = os.path.join(app.config['UPLOAD_DIR'], key_filename)
            
            if not (os.path.exists(cert_file) and os.path.exists(key_file)):
                return jsonify({'success': False, 'message': '上传的证书文件不存在'}), 404
        
        # 使用Python的http.server和ssl模块创建HTTPS服务器
        import http.server
        import socketserver
        import threading
        import socket
        
        # 定义一个简单的HTTP请求处理器
        class SSLVerifyHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                html_content = f'''
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                    <meta charset="UTF-8">
                    <title>SSL证书验证</title>
                    <style>
                        body {{font-family: Arial, sans-serif; margin: 40px; line-height: 1.6;}}
                        h1 {{color: #4CAF50;}}
                        p {{font-size: 16px;}}
                        #countdown {{font-size: 24px; color: #ff6b6b; font-weight: bold;}}
                    </style>
                    <script>
                        window.onload = function() {{
                            var timeLeft = 30;
                            var countdownElement = document.getElementById('countdown');
                            
                            function updateCountdown() {{
                                countdownElement.textContent = timeLeft;
                                if (timeLeft > 0) {{
                                    timeLeft--;
                                    setTimeout(updateCountdown, 1000);
                                }} else {{
                                    window.close();
                                }}
                            }}
                            
                            updateCountdown();
                        }}
                    </script>
                </head>
                <body>
                    <h1>SSL证书验证页面</h1>
                    <p>请检查网址前方是否有不安全提醒，如果没有即通过验证。</p>
                    <p>此页面将在 <span id="countdown">30</span> 秒后自动关闭。</p>
                </body>
                </html>
                '''
                self.wfile.write(html_content.encode('utf-8'))
            
            def log_message(self, format, *args):
                # 重写日志方法，避免在控制台输出过多信息
                pass
        
        # 创建一个临时目录存放证书和私钥
        temp_ssl_dir = os.path.join(os.path.abspath('temp_ssl'))
        os.makedirs(temp_ssl_dir, exist_ok=True)
        
        # 复制证书和私钥到临时目录
        temp_cert = os.path.join(temp_ssl_dir, 'server.crt')
        temp_key = os.path.join(temp_ssl_dir, 'server.key')
        
        shutil.copy2(cert_file, temp_cert)
        shutil.copy2(key_file, temp_key)
        
        # 创建HTTPS服务器
        print("开始创建Python HTTPS服务器...")
        
        # 定义全局变量存储服务器实例和线程
        global https_server
        global https_thread
        
        # 设置服务器端口
        server_port = 16888
        
        # 创建SSL上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(temp_cert, temp_key)
        
        # 创建HTTP服务器
        httpd = http.server.HTTPServer(('0.0.0.0', server_port), SSLVerifyHandler)
        
        # 将服务器包装为HTTPS服务器
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
        # 保存服务器实例到全局变量
        https_server = httpd
        
        # 定义服务器运行函数
        def run_server():
            try:
                print(f"HTTPS服务器正在监听端口 {server_port}...")
                https_server.serve_forever()
            except Exception as e:
                print(f"HTTPS服务器运行出错: {str(e)}")
        
        # 在新线程中启动服务器
        https_thread = threading.Thread(target=run_server)
        https_thread.daemon = True
        https_thread.start()
        
        # 检查服务器是否成功启动
        verify_url = f"https://{address}:{server_port}"
        time.sleep(1)  # 等待一秒，让服务器有时间启动
        try:
            # 尝试连接到服务器
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect((address, server_port))
                print("成功连接到HTTPS服务器")
                # 使用webbrowser模块自动打开验证URL
                import webbrowser
                webbrowser.open(verify_url)
            except Exception as e:
                print(f"连接到HTTPS服务器失败: {str(e)}")
            finally:
                s.close()
        except Exception as e:
            print(f"检查HTTPS服务器状态时出错: {str(e)}")
        # 设置30秒后自动关闭HTTPS服务器
        def stop_https_server():
            try:
                if https_server:
                    print("正在关闭HTTPS服务器...")
                    https_server.shutdown()
                    print("HTTPS服务器已停止")
                    
                    # 清理临时文件
                    try:
                        if os.path.exists(temp_cert):
                            os.remove(temp_cert)
                        if os.path.exists(temp_key):
                            os.remove(temp_key)
                    except Exception as e:
                        print(f"清理临时文件完成")
            except Exception as e:
                print(f"停止HTTPS服务器时出错: {str(e)}")
        
        # 创建定时器
        timer = threading.Timer(30, stop_https_server)
        timer.daemon = True  # 设置为守护线程，这样如果主程序退出，定时器也会退出
        timer.start()
        print(f"已设置30秒后自动关闭HTTPS服务器的定时器")
        
        # 返回成功信息和验证URL
        
        print(f"验证URL: {verify_url}")
        return jsonify({
            'success': True, 
            'message': '验证服务器已启动，30秒后将自动关闭',
            'verify_url': verify_url
        })
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"启动验证服务器时出错: {str(e)}")
        print(f"错误详情:\n{error_trace}")
        
        # 清理可能创建的临时文件
        try:
            if 'temp_cert' in locals() and os.path.exists(temp_cert):
                os.remove(temp_cert)
            if 'temp_key' in locals() and os.path.exists(temp_key):
                os.remove(temp_key)
        except Exception as cleanup_error:
            print(f"清理临时文件时出错: {str(cleanup_error)}")
        
        return jsonify({'success': False, 'message': f'启动验证服务器失败: {str(e)}'}), 500


@app.route('/check_ca_password')
def check_ca_password():
    """检查CA证书是否有密码保护"""
    ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
    
    if os.path.exists(ca_info_file):
        with open(ca_info_file, 'r', encoding='utf-8') as f:
            ca_info = json.load(f)
            has_password = ca_info.get('has_password', False)
            return jsonify({'has_password': has_password})
    
    return jsonify({'has_password': False})

@app.route('/list_certs')
def list_certs():
    """扫描certs目录，根据请求类型返回HTML表格行或JSON格式的证书列表"""
    try:
        # 检查请求是否期望JSON响应
        want_json = request.headers.get('Accept', '').find('application/json') != -1
        page = request.args.get('page', 1, type=int)
        per_page = 8
        certs_dir = app.config['CERTS_DIR']
        html_rows = []
        cert_list = []
        
        # 检查certs目录是否存在
        if not os.path.exists(certs_dir):
            return ''
        
        # 遍历certs目录下的所有子目录
        for cert_name in os.listdir(certs_dir):
            cert_dir = os.path.join(certs_dir, cert_name)
            
            # 只处理目录，并排除CA证书目录
            if not os.path.isdir(cert_dir) or cert_name == 'ca':
                continue
            
            # 检查是否存在证书和私钥文件
            crt_file = os.path.join(cert_dir, f'{cert_name}.crt')
            key_file = os.path.join(cert_dir, f'{cert_name}.key')
            ext_file = os.path.join(cert_dir, f'{cert_name}.ext')
            
            if not (os.path.exists(crt_file) and os.path.exists(key_file)):
                continue
            
            # 从扩展文件中提取IP和域名信息
            ip_addresses = ''
            domains = ''
            
            if os.path.exists(ext_file):
                with open(ext_file, 'r') as f:
                    ext_content = f.read()
                    # 查找subjectAltName行
                    for line in ext_content.split('\n'):
                        if 'subjectAltName' in line:
                            # 提取SAN值
                            san_parts = line.split('=')[1].strip().split(', ')
                            ip_list = []
                            domain_list = []
                            
                            for part in san_parts:
                                if part.startswith('IP:'):
                                    ip_list.append(part[3:])
                                elif part.startswith('DNS:'):
                                    domain_list.append(part[4:])
                            
                            ip_addresses = '\n'.join(ip_list)
                            domains = '\n'.join(domain_list)
                            break
            
            # 计算证书有效期（这里简化处理，使用当前日期加一年）
            valid_until = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
            
            # 处理IP地址显示，转换为HTML列表格式
            if ip_addresses:
                ip_list = ip_addresses.split('\n')
                has_more_ip = len(ip_list) > 3
                ip_html = '<ul class="address-list' + (' has-more' if has_more_ip else '') + '">' 
                for ip in ip_list:  # 显示所有IP地址
                    ip_html += f'<li>{ip}</li>'
                ip_html += '</ul>'
                display_ip = ip_html
            else:
                display_ip = '/'
            
            # 处理域名显示，转换为HTML列表格式
            if domains:
                domain_list = domains.split('\n')
                has_more_domain = len(domain_list) > 3
                domain_html = '<ul class="address-list' + (' has-more' if has_more_domain else '') + '">' 
                for domain in domain_list:  # 显示所有域名
                    domain_html += f'<li>{domain}</li>'
                domain_html += '</ul>'
                display_domains = domain_html
            else:
                display_domains = '/'
            
            # 生成表格行HTML
            html = f'''
    <tr>
        <td><input type="checkbox" class="cert-checkbox" data-cert-name="{cert_name}"></td>
        <td>{cert_name}</td>
        <td>{valid_until}</td>
        <td title="{ip_addresses.replace('/', ', ') if ip_addresses else '/'}" class="ip-address">{display_ip}</td>
        <td title="{domains.replace('/', ', ') if domains else '/'}" class="domain-name">{display_domains}</td>
        <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.crt')}"><i class="fas fa-certificate"></i> {cert_name}.crt</a></td>
        <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.key')}"><i class="fas fa-key"></i> {cert_name}.key</a></td>
    </tr>
    '''
            
            # 添加证书信息到JSON列表
            cert_info = {
                'name': cert_name,
                'valid_until': valid_until,
                'ip_addresses': ip_addresses.split('\n') if ip_addresses else [],
                'domains': domains.split('\n') if domains else [],
                'files': {
                    'crt': f'{cert_name}.crt',
                    'key': f'{cert_name}.key'
                }
            }
            cert_list.append(cert_info)
            html_rows.append(html)
        
        if want_json:
            return jsonify({'certs': cert_list})
        
        if html_rows:
            # 计算总页数
            total_pages = (len(html_rows) + per_page - 1) // per_page
            # 获取当前页的数据
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            current_page_rows = html_rows[start_idx:end_idx]
            
            # 只在总页数大于1时才显示分页HTML
            pagination_html = ''
            if total_pages > 1:
                pagination_html = '<tr class="pagination-row"><td colspan="7"><div class="pagination">'
                if page > 1:
                    pagination_html += f'<a href="#" class="page-link" data-page="{page-1}">上一页</a>'
                for p in range(1, total_pages + 1):
                    if p == page:
                        pagination_html += f'<span class="page-link active">{p}</span>'
                    else:
                        pagination_html += f'<a href="#" class="page-link" data-page="{p}">{p}</a>'
                if page < total_pages:
                    pagination_html += f'<a href="#" class="page-link" data-page="{page+1}">下一页</a>'
                pagination_html += '</div></td></tr>'
            
            return ''.join(current_page_rows) + pagination_html
        else:
            return '<tr class="empty-row"><td colspan="7">创建虚拟机构后，再点击新增按钮申请证书</td></tr>'
    except Exception as e:
        print(f"获取证书列表时出错: {str(e)}")
        return '<tr class="empty-row"><td colspan="7">获取证书列表时出错</td></tr>'

@app.route('/delete_certs', methods=['POST'])
def delete_certs():
    """删除选中的证书"""
    try:
        # 获取要删除的证书名称列表
        cert_names = request.json.get('cert_names', [])
        print(f"收到删除证书请求，证书列表: {cert_names}")
        # 确保cert_names是字符串列表
        cert_names = [str(name) for name in cert_names if name]
        if not cert_names:
            print("未选择任何证书，返回错误")
            return jsonify({
                'status': 'error',
                'message': '请选择要删除的证书',
                'html': '<tr class="empty-row"><td colspan="7">请选择要删除的证书</td></tr>'
            }), 400

        errors = []
        success_count = 0

        # 删除每个选中的证书
        for cert_name in cert_names:
            # 对证书名称进行编码
            encoded_cert_name = quote(cert_name)
            cert_dir = os.path.normpath(os.path.join(app.config['CERTS_DIR'], encoded_cert_name))
            
            if not os.path.exists(cert_dir):
                errors.append(f'证书 {cert_name} 目录不存在')
                continue
                
            if not os.path.isdir(cert_dir):
                errors.append(f'路径 {cert_name} 不是目录')
                continue
            
            try:
                print(f"开始处理证书: {cert_name}, 目录路径: {cert_dir}")
                # 删除证书相关文件
                for file_name in [f'{cert_name}.crt', f'{cert_name}.key', f'{cert_name}.csr', f'{cert_name}.ext']:
                    # 对文件名进行编码
                    encoded_file_name = quote(file_name)
                    file_path = os.path.normpath(os.path.join(cert_dir, encoded_file_name))
                    
                    try:
                        if os.path.exists(file_path):
                            
                            # 尝试打开文件以检查是否被占用
                            try:
                                with open(file_path, 'a'):
                                    pass                               
                            except IOError:
                                print(f"文件被占用，无法删除: {file_path}")
                                errors.append(f'文件 {file_name} 正在被其他程序使用，无法删除')
                                continue
                            os.remove(file_path)
                        else:
                            print(f"文件不存在，跳过: {file_path}")
                    except (PermissionError, OSError) as e:
                        print(f"删除文件失败: {file_path}, 错误: {str(e)}")
                        errors.append(f'删除文件 {file_name} 失败: {str(e)}')
                        continue

                # 检查目录是否为空
                remaining_files = os.listdir(cert_dir)
                if remaining_files:
                    print(f"目录不为空，剩余文件: {remaining_files}")
                    errors.append(f'目录 {cert_name} 不为空，可能有文件正在被占用')
                    continue
                else:
                    print(f"目录为空，可以安全删除: {cert_dir}")

                # 删除证书目录
                try:
                    print(f"准备删除证书目录: {cert_dir}")
                    # 检查目录是否存在
                    if os.path.exists(cert_dir):
                        # 尝试修改文件权限
                        def on_rm_error(func, path, exc_info):
                            print(f"删除时遇到权限错误: {path}")
                            # 尝试修改文件权限
                            os.chmod(path, stat.S_IWRITE)
                            # 再次尝试删除
                            func(path)
                        
                        # 使用shutil.rmtree强制删除目录及其内容
                        print(f"使用shutil.rmtree删除目录: {cert_dir}")
                        shutil.rmtree(cert_dir, onerror=on_rm_error)
                        print(f"成功删除证书目录: {cert_dir}")
                        success_count += 1
                    else:
                        print(f"证书目录不存在: {cert_dir}")
                        errors.append(f'证书目录不存在: {cert_dir}')
                except (PermissionError, OSError) as e:
                    print(f"删除目录失败: {cert_dir}, 错误: {str(e)}")
                    errors.append(f'删除目录 {cert_name} 失败: {str(e)}')
                    print(f"请检查文件权限或是否被其他程序占用")
                    # 不再尝试使用系统命令强制删除

            except Exception as e:
                errors.append(f'处理证书 {cert_name} 时出错: {str(e)}')

        # 准备响应信息
        if success_count > 0:
            # 成功删除至少一个证书，直接返回成功状态
            return jsonify({
                'status': 'success'
            })
        else:
            # 全部失败
            return jsonify({
                'status': 'error',
                'message': '删除证书失败'
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'删除证书时出错: {str(e)}',
            'html': '<tr class="empty-row"><td colspan="7">删除证书时出错，请稍后重试</td></tr>'
        }), 500

# 初始化代理数据文件
def init_proxy_data_file():
    proxy_data_file = app.config.get('PROXY_DATA_FILE')
    if not proxy_data_file:
        app.config['PROXY_DATA_FILE'] = 'proxy/proxy_data.json'
        proxy_data_file = app.config['PROXY_DATA_FILE']
    
    if not os.path.exists(proxy_data_file):
        with open(proxy_data_file, 'w', encoding='utf-8') as f:
            json.dump([], f)
    return proxy_data_file

# 确保代理数据文件存在
init_proxy_data_file()

@app.route('/get_proxy_list', methods=['GET'])
def get_proxy_list():
    try:
        # 获取代理数据文件路径
        proxy_data_file = app.config.get('PROXY_DATA_FILE')
        if not os.path.exists(proxy_data_file):
            # 如果文件不存在，初始化一个空列表
            return jsonify({
                'success': True,
                'proxies': []
            })
        
        # 读取代理数据
        with open(proxy_data_file, 'r', encoding='utf-8') as f:
            proxy_data = json.load(f)
        
        return jsonify({
            'success': True,
            'proxies': proxy_data
        })
    except Exception as e:
        print(f"获取代理列表时出错: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取代理列表时出错: {str(e)}',
            'proxies': []
        }), 500

@app.route('/delete_proxy', methods=['POST'])
def delete_proxy():
    try:
        # 获取要删除的代理ID列表
        proxy_ids = request.json.get('proxy_ids', [])
        if not proxy_ids:
            return jsonify({
                'success': False,
                'message': '请选择要删除的代理服务'
            }), 400

        # 获取代理数据文件路径
        proxy_data_file = os.path.join('proxy', 'proxy_data.json')
        if not os.path.exists(proxy_data_file):
            return jsonify({
                'success': False,
                'message': '代理数据文件不存在'
            }), 404

        # 读取现有数据
        with open(proxy_data_file, 'r', encoding='utf-8') as f:
            proxies = json.load(f)

        # 记录删除的代理和未找到的代理
        deleted_proxies = []
        not_found_proxies = []

        # 过滤出要保留的代理和要删除的代理
        new_proxies = []
        # 确保proxy_ids中的所有ID都是字符串类型
        proxy_ids = [str(pid) for pid in proxy_ids]
        for proxy in proxies:
            if str(proxy.get('id')) in proxy_ids:
                # 尝试停止服务
                proxy_id = str(proxy.get('id'))
                toml_path = f"./toml/{proxy_id}.toml"
                cmd = f'wmic process where "name=\'proxy.exe\' AND CommandLine LIKE \'%rhttp -c {toml_path}%\'" get ProcessId'
                
                try:
                    # 执行命令获取进程ID
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                    output_lines = result.stdout.strip().split('\n')
                    
                    # 如果有进程ID，尝试终止进程
                    if len(output_lines) > 1:
                        pid = output_lines[-1].strip()
                        if pid.isdigit():
                            try:
                                os.kill(int(pid), 9)
                                print(f"已停止进程 {pid}")
                            except Exception as kill_error:
                                print(f"停止进程 {pid} 失败: {str(kill_error)}")
                except Exception as e:
                    print(f"获取进程ID失败: {str(e)}")
                
                deleted_proxies.append(proxy)
            else:
                new_proxies.append(proxy)

        # 检查是否有未找到的代理
        not_found_proxies = [proxy_id for proxy_id in proxy_ids if proxy_id not in [p.get('id') for p in deleted_proxies]]

        # 保存更新后的数据
        with open(proxy_data_file, 'w', encoding='utf-8') as f:
            json.dump(new_proxies, f, ensure_ascii=False, indent=2)

        # 返回删除结果
        return jsonify({
            'success': True,
            'deleted': [p.get('id') for p in deleted_proxies],
            'not_found': not_found_proxies,
            'message': '代理服务删除成功'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'删除代理服务失败：{str(e)}'
        }), 500

@app.route('/create_proxy', methods=['POST'])
def create_proxy():
    try:
        # 获取表单数据
        service_name = request.form.get('service_name')
        original_url = request.form.get('original_url')
        proxy_url = request.form.get('proxy_url')
        cert_type = request.form.get('cert_type')

        # 验证必填字段
        if not all([service_name, original_url, proxy_url]):
            return jsonify({
                'success': False,
                'message': '请填写所有必填字段'
            }), 400

        # 根据证书类型获取证书文件
        cert_filename = None
        key_filename = None
        cert_id = None
        
        if cert_type == 'qilin':
            cert_id = request.form.get('cert_id')
            if not cert_id:
                return jsonify({
                    'success': False,
                    'message': '请选择证书'
                }), 400

            # 获取qilin ssl证书文件路径
            cert_dir = os.path.join(app.config['CERTS_DIR'], cert_id)
            cert_file = os.path.join(cert_dir, f'{cert_id}.crt')
            key_file = os.path.join(cert_dir, f'{cert_id}.key')

            if not (os.path.exists(cert_file) and os.path.exists(key_file)):
                return jsonify({
                    'success': False,
                    'message': '证书文件不存在'
                }), 404
        else:
            # 处理自定义证书
            cert_filename = request.form.get('cert_filename')
            key_filename = request.form.get('key_filename')
            
            # 处理上传的文件
            cert_file = request.files.get('cert_file')
            key_file = request.files.get('key_file')
            
            # 如果没有提供现有证书文件名且没有上传任何文件
            if (not cert_filename and not cert_file) or (not key_filename and not key_file):
                return jsonify({
                    'success': False,
                    'message': '请提供证书和私钥文件'
                }), 400

            # 处理证书文件
            if cert_file:
                if cert_file.filename == '':
                    return jsonify({
                        'success': False,
                        'message': '请选择有效的证书文件'
                    }), 400
                cert_filename = secure_filename(cert_file.filename)
                cert_file_path = os.path.join(app.config['UPLOAD_DIR'], cert_filename)
                cert_file.save(cert_file_path)
            
            # 处理私钥文件
            if key_file:
                if key_file.filename == '':
                    return jsonify({
                        'success': False,
                        'message': '请选择有效的私钥文件'
                    }), 400
                key_filename = secure_filename(key_file.filename)
                key_file_path = os.path.join(app.config['UPLOAD_DIR'], key_filename)
                key_file.save(key_file_path)
            else:
                # 验证现有证书文件是否存在
                cert_file_path = os.path.join(app.config['UPLOAD_DIR'], cert_filename)
                key_file_path = os.path.join(app.config['UPLOAD_DIR'], key_filename)
                if not (os.path.exists(cert_file_path) and os.path.exists(key_file_path)):
                    return jsonify({
                        'success': False,
                        'message': '证书文件不存在'
                    }), 404


        # 获取证书有效期
        if cert_type == 'qilin':
            # 从证书列表中获取有效期
            cert_list_file = os.path.join(app.config['CERTS_DIR'], cert_id, f'{cert_id}.crt')
            try:
                # 使用本地OpenSSL命令获取证书有效期
                openssl_path = os.path.join(app.config['BASE_DIR'], 'bin', 'openssl.exe')
                cmd = [openssl_path, 'x509', '-in', cert_list_file, '-enddate', '-noout']
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=app.config['BASE_DIR'])
                if result.stderr:
                    print(f"OpenSSL命令警告: {result.stderr}")
                # 解析输出格式：notAfter=Dec 31 23:59:59 2024 GMT
                expiry_str = result.stdout.strip().split('=')[1]
                expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y GMT')
                cert_expiry = expiry_date.strftime('%Y-%m-%d')
            except Exception as e:
                print(f"获取证书有效期失败: {str(e)}")
                cert_expiry = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
        else:
            # 读取上传的证书文件获取有效期
            try:
                openssl_path = os.path.join(app.config['BASE_DIR'], 'bin', 'openssl.exe')
                cmd = [openssl_path, 'x509', '-in', cert_file_path, '-enddate', '-noout']
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=app.config['BASE_DIR'])
                if result.stderr:
                    print(f"OpenSSL命令警告: {result.stderr}")
                # 解析输出格式：notAfter=Dec 31 23:59:59 2024 GMT
                expiry_str = result.stdout.strip().split('=')[1]
                expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y GMT')
                cert_expiry = expiry_date.strftime('%Y-%m-%d')
            except Exception as e:
                print(f"获取证书有效期失败: {str(e)}")
                cert_expiry = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
        
        # 创建代理数据
        proxy_data = {
            'id': service_name,
            'service_name': service_name,
            'original_url': original_url,
            'proxy_url': proxy_url,
            'cert_type': cert_type,
            'cert_id': cert_id,
            'cert_filename': cert_filename,
            'key_filename': key_filename,
            'cert_expiry': cert_expiry,
            'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 保存到代理数据文件
        proxy_data_file = app.config.get('PROXY_DATA_FILE')
        if not os.path.exists(proxy_data_file):
            # 如果文件不存在，创建一个空列表
            proxies = []
        else:
            # 读取现有数据
            with open(proxy_data_file, 'r', encoding='utf-8') as f:
                proxies = json.load(f)
        
        # 检查是否已存在同名代理
        for i, proxy in enumerate(proxies):
            if proxy.get('id') == service_name:
                # 如果存在同名代理，更新它
                proxies[i] = proxy_data
                break
        else:
            # 如果不存在同名代理，添加新代理
            proxies.append(proxy_data)
        
        # 保存更新后的数据
        with open(proxy_data_file, 'w', encoding='utf-8') as f:
            json.dump(proxies, f, ensure_ascii=False, indent=2)

        return jsonify({
            'success': True,
            'proxy_id': service_name,
            'cert_expiry': cert_expiry,
            'message': '反向代理创建成功'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'创建反向代理失败：{str(e)}'
        }), 500

@app.route('/run_proxy', methods=['POST'])
def run_proxy():
    try:
        print("开始处理run_proxy请求...")
        # 获取要运行的代理ID
        proxy_id = request.json.get('proxy_id')
        print(f"接收到的proxy_id: {proxy_id}")
        if not proxy_id:
            print("错误：未提供proxy_id")
            return jsonify({
                'success': False,
                'message': '请选择要运行的代理服务'
            }), 400

        # 获取代理数据文件路径
        proxy_data_file = app.config.get('PROXY_DATA_FILE')
        print(f"代理数据文件路径: {proxy_data_file}")
        if not os.path.exists(proxy_data_file):
            print(f"错误：代理数据文件不存在: {proxy_data_file}")
            return jsonify({
                'success': False,
                'message': '代理数据文件不存在'
            }), 404

        # 读取代理数据
        print("开始读取代理数据文件...")
        with open(proxy_data_file, 'r', encoding='utf-8') as f:
            proxies = json.load(f)
        print(f"成功读取代理数据，共有{len(proxies)}条记录")

        # 查找指定的代理
        proxy_data = None
        # 确保proxy_id是字符串类型
        proxy_id = str(proxy_id)
        for proxy in proxies:
            # 将proxy中的id也转换为字符串进行比较
            if str(proxy.get('id')) == proxy_id:
                proxy_data = proxy
                print(f"找到匹配的代理数据: {json.dumps(proxy, ensure_ascii=False)}")
                break

        if not proxy_data:
            print(f"错误：未找到ID为{proxy_id}的代理服务")
            return jsonify({
                'success': False,
                'message': f'未找到ID为{proxy_id}的代理服务'
            }), 404

        # 设置反向代理工作目录
        proxy_dir = os.path.join(app.config['BASE_DIR'], 'proxy')
        toml_dir = os.path.join(proxy_dir, 'toml')
        cert_dir = os.path.join(proxy_dir, 'cert')

        # 确保目录存在
        os.makedirs(toml_dir, exist_ok=True)
        os.makedirs(cert_dir, exist_ok=True)

        # 准备证书文件
        cert_path = None
        key_path = None

        if proxy_data.get('cert_type') == 'qilin':
            print("处理qilin类型证书...")
            # 使用qilin证书
            cert_id = proxy_data.get('cert_id')
            print(f"获取到的cert_id: {cert_id}")
            if not cert_id:
                print("错误：证书ID不存在")
                return jsonify({
                    'success': False,
                    'message': '证书ID不存在'
                }), 400

            # 源证书路径
            src_cert = os.path.join(app.config['CERTS_DIR'], cert_id, f'{cert_id}.crt')
            src_key = os.path.join(app.config['CERTS_DIR'], cert_id, f'{cert_id}.key')

            # 检查源证书文件是否存在
            if not os.path.exists(src_cert) or not os.path.exists(src_key):
                print(f"错误：证书文件不存在，cert存在: {os.path.exists(src_cert)}, key存在: {os.path.exists(src_key)}")
                return jsonify({
                    'success': False,
                    'message': '证书文件不存在'
                }), 404

            # 目标证书路径
            cert_path = os.path.join(cert_dir, f'{proxy_id}.crt')
            key_path = os.path.join(cert_dir, f'{proxy_id}.key')
            print(f"目标证书路径: {cert_path}")
            print(f"目标私钥路径: {key_path}")

            # 复制证书文件
            try:
                # 如果目标文件已存在，先删除
                if os.path.exists(cert_path):
                    os.remove(cert_path)
                if os.path.exists(key_path):
                    os.remove(key_path)
                    
                shutil.copy2(src_cert, cert_path)
                print(f"成功复制证书文件: {src_cert} -> {cert_path}")
                shutil.copy2(src_key, key_path)
                print(f"成功复制私钥文件: {src_key} -> {key_path}")
            except Exception as e:
                print(f"复制证书文件时出错: {str(e)}")
                return jsonify({
                    'success': False,
                    'message': f'复制证书文件失败: {str(e)}'
                }), 500
        else:
            # 使用自定义证书
            cert_filename = proxy_data.get('cert_filename')
            key_filename = proxy_data.get('key_filename')

            if not cert_filename or not key_filename:
                return jsonify({
                    'success': False,
                    'message': '证书文件名不存在'
                }), 400

            # 源证书路径
            src_cert = os.path.join(app.config['UPLOAD_DIR'], cert_filename)
            src_key = os.path.join(app.config['UPLOAD_DIR'], key_filename)

            # 检查源证书文件是否存在
            if not os.path.exists(src_cert) or not os.path.exists(src_key):
                print(f"错误：证书文件不存在，cert存在: {os.path.exists(src_cert)}, key存在: {os.path.exists(src_key)}")
                return jsonify({
                    'success': False,
                    'message': '证书文件不存在'
                }), 404

            # 目标证书路径
            cert_path = os.path.join(cert_dir, f'{proxy_id}.crt')
            key_path = os.path.join(cert_dir, f'{proxy_id}.key')
            print(f"目标证书路径: {cert_path}")
            print(f"目标私钥路径: {key_path}")

            # 复制证书文件
            try:
                # 如果目标文件已存在，先删除
                if os.path.exists(cert_path):
                    os.remove(cert_path)
                if os.path.exists(key_path):
                    os.remove(key_path)
                    
                shutil.copy2(src_cert, cert_path)
                print(f"成功复制证书文件: {src_cert} -> {cert_path}")
                shutil.copy2(src_key, key_path)
                print(f"成功复制私钥文件: {src_key} -> {key_path}")
            except Exception as e:
                print(f"复制证书文件时出错: {str(e)}")
                return jsonify({
                    'success': False,
                    'message': f'复制证书文件失败: {str(e)}'
                }), 500

        # 解析原始URL和代理URL
        original_url = proxy_data.get('original_url')
        proxy_url = proxy_data.get('proxy_url')

        # 提取upstream（去除http://或https://后的地址）
        upstream = original_url.split('://', 1)[1] if '://' in original_url else original_url

        # 生成toml配置文件内容
        toml_content = f'''
# 反向代理配置文件 - {proxy_data.get('service_name')}
[[host]]
bind="{proxy_url}/"
tlscert="./cert/{proxy_id}.crt"
tlskey="./cert/{proxy_id}.key"
target="{original_url}/"
upstream="{upstream}"
timeout=3000
'''

        # 保存toml配置文件
        toml_file_path = os.path.join(toml_dir, f'{proxy_id}.toml')
        with open(toml_file_path, 'w', encoding='utf-8') as f:
            f.write(toml_content)

        # 运行反向代理命令
        proxy_exe = os.path.join(proxy_dir, 'proxy.exe')
        cmd = [proxy_exe, 'rhttp', '-c', f'./toml/{proxy_id}.toml']
        print(f"准备执行命令: {' '.join(cmd)}")
        print(f"工作目录: {proxy_dir}")

        # 使用subprocess启动进程
        try:
            process = subprocess.Popen(cmd, cwd=proxy_dir)
            print(f"成功启动进程，PID: {process.pid}")
        except Exception as e:
            print(f"启动进程失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'启动代理进程失败: {str(e)}'
            }), 500
 
        # 更新proxy_data.json中的进程号和状态
        for proxy in proxies:
            if proxy.get('id') == proxy_id:
                proxy['pid'] = process.pid
                proxy['status'] = 'on'  # 添加状态参数
                break

        # 保存更新后的proxy_data.json
        with open(proxy_data_file, 'w', encoding='utf-8') as f:
            json.dump(proxies, f, ensure_ascii=False, indent=2)

        return jsonify({
            'success': True,
            'message': f'反向代理服务 {proxy_id} 已启动',
            'pid': process.pid
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'启动反向代理服务失败：{str(e)}'
        }), 500

@app.route('/stop_proxy', methods=['POST'])
def stop_proxy():
    try:
        # 获取要停止的代理ID
        proxy_id = request.json.get('proxy_id')
        if not proxy_id:
            return jsonify({
                'success': False,
                'message': '请提供要停止的代理ID'
            }), 400

        # 构建wmic命令查询进程ID
        toml_path = f"./toml/{proxy_id}.toml"
        cmd = f'wmic process where "name=\'proxy.exe\' AND CommandLine LIKE \'%rhttp -c {toml_path}%\'" get ProcessId'
        
        # 执行命令获取进程ID
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.stderr:
            return jsonify({
                'success': False,
                'message': f'获取进程ID失败：{result.stderr}'
            }), 500

        # 解析输出获取进程ID
        output_lines = result.stdout.strip().split('\n')
        if len(output_lines) <= 1:  # 只有标题行或没有输出
            return jsonify({
                'success': True,
                'message': '进程已不存在'
            })

        # 获取最后一行的数字作为pid
        pid = output_lines[-1].strip()
        if not pid.isdigit():
            return jsonify({
                'success': False,
                'message': '无法获取有效的进程ID'
            }), 500

        pid = int(pid)
        print(f"正在尝试停止进程，PID: {pid}")
        try:
            # 尝试终止进程
            os.kill(pid, 9)
            print(f"进程 {pid} 已成功终止")
            
            # 更新proxy_data.json中的状态
            proxy_data_file = app.config.get('PROXY_DATA_FILE')
            if os.path.exists(proxy_data_file):
                with open(proxy_data_file, 'r', encoding='utf-8') as f:
                    proxies = json.load(f)
                
                # 更新状态为off
                for proxy in proxies:
                    if str(proxy.get('id')) == str(proxy_id):
                        proxy['status'] = 'off'  # 添加状态参数
                        break
                
                # 保存更新后的proxy_data.json
                with open(proxy_data_file, 'w', encoding='utf-8') as f:
                    json.dump(proxies, f, ensure_ascii=False, indent=2)
            
            return jsonify({
                'success': True,
                'message': '代理服务已停止'
            })
        except ProcessLookupError:
            print(f"进程 {pid} 已不存在")
            return jsonify({
                'success': True,
                'message': '进程已不存在'
            })
        except Exception as e:
            error_msg = f"停止进程 {pid} 时发生错误: {str(e)}"
            print(error_msg)
            return jsonify({
                'success': False,
                'message': error_msg
            }), 500

    except Exception as e:
        error_msg = f"停止反向代理服务失败：{str(e)}"
        print(error_msg)
        return jsonify({
            'success': False,
            'message': error_msg
        }), 500

@app.route('/get_proxy_pid/<service_id>', methods=['GET'])
def get_proxy_pid(service_id):
    try:
        # 读取proxy_data.json文件获取服务信息
        proxy_data_file = os.path.join('proxy', 'proxy_data.json')
        if not os.path.exists(proxy_data_file):
            return jsonify({'success': True, 'pid': None})
            
        with open(proxy_data_file, 'r', encoding='utf-8') as f:
            proxy_services = json.load(f)
            
        # 查找指定服务ID的配置
        service = next((s for s in proxy_services if s['id'] == service_id), None)
        if not service:
            return jsonify({'success': True, 'pid': None})
            
        # 构建wmic命令查询进程ID
        toml_path = f"./toml/{service_id}.toml"
        cmd = f'wmic process where "name=\'proxy.exe\' AND CommandLine LIKE \'%rhttp -c {toml_path}%\'" get ProcessId'
        
        # 执行命令获取进程ID
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.stderr:

            return jsonify({'success': True, 'pid': None})
        
        # 解析输出获取进程ID
        output_lines = result.stdout.strip().split('\n')

        
        # 获取最后一行的数字作为pid
        if len(output_lines) > 0:
            last_line = output_lines[-1].strip()
            if last_line.isdigit():
                return jsonify({'success': True, 'pid': int(last_line)})
        
        return jsonify({'success': True, 'pid': None})
        
    except Exception as e:
        print(f"发生异常: {str(e)}")
        return jsonify({'success': True, 'pid': None})


def auto_start_proxy_services():
    """根据proxy_data.json中的status状态自动启动代理服务"""
    try:
        print("正在检查并启动代理服务...")
        # 获取代理数据文件路径
        proxy_data_file = app.config.get('PROXY_DATA_FILE')
        if not proxy_data_file or not os.path.exists(proxy_data_file):
            print("代理数据文件不存在，跳过自动启动")
            return
            
        # 读取代理数据
        with open(proxy_data_file, 'r', encoding='utf-8') as f:
            proxies = json.load(f)
            
        # 设置反向代理工作目录
        proxy_dir = os.path.join(app.config['BASE_DIR'], 'proxy')
        toml_dir = os.path.join(proxy_dir, 'toml')
        cert_dir = os.path.join(proxy_dir, 'cert')
        
        # 确保目录存在
        os.makedirs(toml_dir, exist_ok=True)
        os.makedirs(cert_dir, exist_ok=True)
        
        # 遍历所有代理服务
        for proxy_data in proxies:
            # 检查状态是否为on
            if proxy_data.get('status') != 'on':
                print(f"代理服务 {proxy_data.get('id')} 状态为 {proxy_data.get('status')}，跳过启动")
                continue
                
            proxy_id = proxy_data.get('id')
            print(f"准备启动代理服务: {proxy_id}")
            
            # 准备证书文件
            if proxy_data.get('cert_type') == 'qilin':
                # 使用qilin证书
                cert_id = proxy_data.get('cert_id')
                if not cert_id:
                    print(f"代理服务 {proxy_id} 的证书ID不存在，跳过启动")
                    continue
                    
                # 源证书路径
                src_cert = os.path.join(app.config['CERTS_DIR'], cert_id, f'{cert_id}.crt')
                src_key = os.path.join(app.config['CERTS_DIR'], cert_id, f'{cert_id}.key')
                
                # 检查源证书文件是否存在
                if not os.path.exists(src_cert) or not os.path.exists(src_key):
                    print(f"代理服务 {proxy_id} 的证书文件不存在，跳过启动")
                    continue
                    
                # 目标证书路径
                cert_path = os.path.join(cert_dir, f'{proxy_id}.crt')
                key_path = os.path.join(cert_dir, f'{proxy_id}.key')
                
                # 复制证书文件
                try:
                    # 如果目标文件已存在，先删除
                    if os.path.exists(cert_path):
                        os.remove(cert_path)
                    if os.path.exists(key_path):
                        os.remove(key_path)
                        
                    shutil.copy2(src_cert, cert_path)
                    shutil.copy2(src_key, key_path)
                except Exception as e:
                    print(f"复制证书文件失败: {str(e)}，跳过启动代理服务 {proxy_id}")
                    continue
            else:
                # 使用自定义证书
                cert_filename = proxy_data.get('cert_filename')
                key_filename = proxy_data.get('key_filename')
                
                if not cert_filename or not key_filename:
                    print(f"代理服务 {proxy_id} 的证书文件名不存在，跳过启动")
                    continue
                    
                # 源证书路径
                src_cert = os.path.join(app.config['UPLOAD_DIR'], cert_filename)
                src_key = os.path.join(app.config['UPLOAD_DIR'], key_filename)
                
                # 检查源证书文件是否存在
                if not os.path.exists(src_cert) or not os.path.exists(src_key):
                    print(f"代理服务 {proxy_id} 的证书文件不存在，跳过启动")
                    continue
                    
                # 目标证书路径
                cert_path = os.path.join(cert_dir, f'{proxy_id}.crt')
                key_path = os.path.join(cert_dir, f'{proxy_id}.key')
                
                # 复制证书文件
                try:
                    # 如果目标文件已存在，先删除
                    if os.path.exists(cert_path):
                        os.remove(cert_path)
                    if os.path.exists(key_path):
                        os.remove(key_path)
                        
                    shutil.copy2(src_cert, cert_path)
                    shutil.copy2(src_key, key_path)
                except Exception as e:
                    print(f"复制证书文件失败: {str(e)}，跳过启动代理服务 {proxy_id}")
                    continue
            
            # 解析原始URL和代理URL
            original_url = proxy_data.get('original_url')
            proxy_url = proxy_data.get('proxy_url')
            
            # 提取upstream（去除http://或https://后的地址）
            upstream = original_url.split('://', 1)[1] if '://' in original_url else original_url
            
            # 生成toml配置文件内容
            toml_content = f'''
# 反向代理配置文件 - {proxy_data.get('service_name')}
[[host]]
bind="{proxy_url}/"
tlscert="./cert/{proxy_id}.crt"
tlskey="./cert/{proxy_id}.key"
target="{original_url}/"
upstream="{upstream}"
timeout=3000
'''
            
            # 保存toml配置文件
            toml_file_path = os.path.join(toml_dir, f'{proxy_id}.toml')
            with open(toml_file_path, 'w', encoding='utf-8') as f:
                f.write(toml_content)
            
            # 运行反向代理命令
            proxy_exe = os.path.join(proxy_dir, 'proxy.exe')
            cmd = [proxy_exe, 'rhttp', '-c', f'./toml/{proxy_id}.toml']
            
            # 使用subprocess启动进程
            try:
                process = subprocess.Popen(cmd, cwd=proxy_dir)
                print(f"成功启动代理服务 {proxy_id}，PID: {process.pid}")
                
                # 更新proxy_data.json中的进程号
                for proxy in proxies:
                    if proxy.get('id') == proxy_id:
                        proxy['pid'] = process.pid
                        break
                
                # 保存更新后的proxy_data.json
                with open(proxy_data_file, 'w', encoding='utf-8') as f:
                    json.dump(proxies, f, ensure_ascii=False, indent=2)
                    
            except Exception as e:
                print(f"启动代理服务 {proxy_id} 失败: {str(e)}")
    except Exception as e:
        print(f"自动启动代理服务时出错: {str(e)}")

if __name__ == '__main__':
    # 在应用启动前，根据proxy_data.json中的status状态自动启动代理服务
    auto_start_proxy_services()
    
    app.run(host='0.0.0.0', port=2002, debug=True)