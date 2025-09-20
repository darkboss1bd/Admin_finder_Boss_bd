import os
import sys
import requests
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

# Darkboss1BD branding and information
BRAND = """
\033[1;31m
  ____             _                 ____   ___  ____  
 |  _ \\  __ _ _ __| | __  ___ _ __  | ___| / _ \\|  _ \\ 
 | | | |/ _` | '__| |/ / / __| '_ \\ |___ \\| | | | |_) |
 | |_| | (_| | |  |   <  \\__ \\ |_) | ___) | |_| |  _ < 
 |____/ \\__,_|_|  |_|\\_\\ |___/ .__/ |____/ \\___/|_| \\_\\
                             |_|                       
\033[0m
\033[1;32m
        Admin Panel Finder 500+ Admin  Paths
           Created by: darkboss1bd
\033[0m
"""

TELEGRAM_ID = "https://t.me/darkvaiadmin"
WEBSITE = "https://serialkey.top/"
TELEGRAM_CHANNEL = "https://t.me/windowspremiumkey"

# Admin panel paths list (500+ entries)
ADMIN_PATHS = [
    "admin", "administrator", "adminpanel", "admin_area", "admin-login", 
    "admin_login", "admin1", "admin2", "admin4", "admin5", "moderator", 
    "webadmin", "adminarea", "panel-administracion", "adminLogin", 
    "useradmin", "sysadmin", "admin/admin", "admin/account", 
    "admin/login", "admin/admin", "admin_area/login", "admin_", 
    "administrator/login", "adminportal", "admincontrol", "admincp", 
    "admin_cp", "cp", "administratoraccount", "adm", "account", 
    "adminaccount", "administration", "administer", "loginadmin", 
    "adminhome", "admin_login.php", "admin_login.html", "admincontrol.php", 
    "admin-control.php", "adminpanel.php", "adminpanel.html", 
    "admin/cp.php", "cp.php", "administrator.php", "administrator.html", 
    "login.php", "login.html", "modelsearch/admin", "administrator/index.php", 
    "administrator/login.php", "administrator/account.php", 
    "administrator.html", "admin.html", "admin/cp.php", "cp.php", 
    "adminzone", "admin_zone", "admin_", "admin_area/admin", 
    "admin_area/login.php", "panel_admin", "admin_area/account.php", 
    "admin_area/index.php", "bb-admin", "bb-admin/admin", 
    "bb-admin/login.php", "bb-admin/index.php", "acceso", "acceso.php", 
    "acceso.html", "admin/admin_login.php", "admin/admin_login.html", 
    "admin_login.php", "admin_login.html", "admin/account.php", 
    "admin/account.html", "admin/index.php", "admin/index.html", 
    "admin/login.php", "admin/login.html", "admin/home.php", 
    "admin/home.html", "admin/controlpanel.php", "admin/controlpanel.html", 
    "admin.php", "admin.html", "admin/cp.php", "admin/cp.html", 
    "cp.php", "cp.html", "administrator/index.php", 
    "administrator/index.html", "administrator/login.php", 
    "administrator/login.html", "administrator/account.php", 
    "administrator/account.html", "administrator.php", "administrator.html", 
    "login.php", "login.html", "modelsearch/login.php", 
    "modelsearch/login.html", "moderator.php", "moderator.html", 
    "moderator/login.php", "moderator/login.html", "moderator/admin.php", 
    "moderator/admin.html", "moderator/index.php", "moderator/index.html", 
    "admin/cp.php", "cp.php", "adminpanel.php", "adminpanel.html", 
    "admin/admin_login.php", "admin/admin_login.html", 
    "admin_login.php", "admin_login.html", "panel_admin.php", 
    "panel_admin.html", "admin_area/admin.php", "admin_area/admin.html", 
    "admin_area/login.php", "admin_area/login.html", 
    "admin_area/index.php", "admin_area/index.html", 
    "admin/controlpanel.php", "admin/controlpanel.html", 
    "admin.php", "admin.html", "admin/cp.php", "admin/cp.html", 
    "cp.php", "cp.html", "administrator/index.php", 
    "administrator/index.html", "administrator/login.php", 
    "administrator/login.html", "administrator/account.php", 
    "administrator/account.html", "administrator.php", "administrator.html", 
    "login.php", "login.html", "modelsearch/login.php", 
    "modelsearch/login.html", "moderator.php", "moderator.html", 
    "moderator/login.php", "moderator/login.html", "moderator/admin.php", 
    "moderator/admin.html", "moderator/index.php", "moderator/index.html", 
    "admin/cp.php", "cp.php", "adminpanel.php", "adminpanel.html", 
    "admin/admin_login.php", "admin/admin_login.html", 
    "admin_login.php", "admin_login.html", "panel_admin.php", 
    "panel_admin.html", "admin_area/admin.php", "admin_area/admin.html", 
    "admin_area/login.php", "admin_area/login.html", 
    "admin_area/index.php", "admin_area/index.html", 
    "admin/controlpanel.php", "admin/controlpanel.html", 
    "admin.php", "admin.html", "admin/cp.php", "admin/cp.html", 
    "cp.php", "cp.html", "administrator/index.php", 
    "administrator/index.html", "administrator/login.php", 
    "administrator/login.html", "administrator/account.php", 
    "administrator/account.html", "administrator.php", "administrator.html", 
    "login.php", "login.html", "modelsearch/login.php", 
    "modelsearch/login.html", "moderator.php", "moderator.html", 
    "moderator/login.php", "moderator/login.html", "moderator/admin.php", 
    "moderator/admin.html", "moderator/index.php", "moderator/index.html", 
    "admin/cp.php", "cp.php", "adminpanel.php", "adminpanel.html", 
    "wp-admin", "wp-admin/", "wp-admin/login.php", "wp-login.php", 
    "wordpress/wp-admin", "wordpress/wp-login.php", "blog/wp-admin", 
    "blog/wp-login.php", "wp/wp-admin", "wp/wp-login.php", 
    "wordpress/admin", "wordpress/login", "blog/admin", "blog/login", 
    "wp/admin", "wp/login", "administr", "administr/login.php", 
    "administr/index.php", "administr/admin.php", "administr/account.php", 
    "administr/login.html", "administr/index.html", "administr/admin.html", 
    "administr/account.html", "administr.php", "administr.html", 
    "admin/administrator", "admin/administrator.php", 
    "admin/administrator.html", "admin/administrator/login.php", 
    "admin/administrator/login.html", "admin/administrator/account.php", 
    "admin/administrator/account.html", "admin/administrator/index.php", 
    "admin/administrator/index.html", "admin/administr", 
    "admin/administr.php", "admin/administr.html", 
    "admin/administr/login.php", "admin/administr/login.html", 
    "admin/administr/account.php", "admin/administr/account.html", 
    "admin/administr/index.php", "admin/administr/index.html", 
    "admin/admin", "admin/account", "admin/index", "admin/login", 
    "admin/home", "admin/controlpanel", "admin/cp", "administrator/admin", 
    "administrator/account", "administrator/index", "administrator/login", 
    "administrator/home", "administrator/controlpanel", "administrator/cp", 
    "login/admin", "login/administrator", "login/moderation", 
    "login/moderator", "account/admin", "account/administrator", 
    "account/moderation", "account/moderator", "cp/admin", "cp/administrator", 
    "cp/moderation", "cp/moderator", "controlpanel/admin", 
    "controlpanel/administrator", "controlpanel/moderation", 
    "controlpanel/moderator", "admincp", "admincp.php", "admincp.html", 
    "administratorcp", "administratorcp.php", "administratorcp.html", 
    "moderatorcp", "moderatorcp.php", "moderatorcp.html", "administercp", 
    "administercp.php", "administercp.html", "admin_cp", "admin_cp.php", 
    "admin_cp.html", "administrator_cp", "administrator_cp.php", 
    "administrator_cp.html", "moderator_cp", "moderator_cp.php", 
    "moderator_cp.html", "administer_cp", "administer_cp.php", 
    "administer_cp.html", "controlpanel", "controlpanel.php", 
    "controlpanel.html", "admin_control", "admin_control.php", 
    "admin_control.html", "administrator_control", "administrator_control.php", 
    "administrator_control.html", "moderator_control", "moderator_control.php", 
    "moderator_control.html", "administer_control", "administer_control.php", 
    "administer_control.html", "panel", "panel.php", "panel.html", 
    "admin_panel", "admin_panel.php", "admin_panel.html", 
    "administrator_panel", "administrator_panel.php", "administrator_panel.html", 
    "moderator_panel", "moderator_panel.php", "moderator_panel.html", 
    "administer_panel", "administer_panel.php", "administer_panel.html", 
    "management", "management.php", "management.html", "admin_management", 
    "admin_management.php", "admin_management.html", "administrator_management", 
    "administrator_management.php", "administrator_management.html", 
    "moderator_management", "moderator_management.php", "moderator_management.html", 
    "administer_management", "administer_management.php", "administer_management.html", 
    "console", "console.php", "console.html", "admin_console", 
    "admin_console.php", "admin_console.html", "administrator_console", 
    "administrator_console.php", "administrator_console.html", 
    "moderator_console", "moderator_console.php", "moderator_console.html", 
    "administer_console", "administer_console.php", "administer_console.html", 
    "backend", "backend.php", "backend.html", "admin_backend", 
    "admin_backend.php", "admin_backend.html", "administrator_backend", 
    "administrator_backend.php", "administrator_backend.html", 
    "moderator_backend", "moderator_backend.php", "moderator_backend.html", 
    "administer_backend", "administer_backend.php", "administer_backend.html", 
    "system", "system.php", "system.html", "admin_system", 
    "admin_system.php", "admin_system.html", "administrator_system", 
    "administrator_system.php", "administrator_system.html", 
    "moderator_system", "moderator_system.php", "moderator_system.html", 
    "administer_system", "administer_system.php", "administer_system.html", 
    "dashboard", "dashboard.php", "dashboard.html", "admin_dashboard", 
    "admin_dashboard.php", "admin_dashboard.html", "administrator_dashboard", 
    "administrator_dashboard.php", "administrator_dashboard.html", 
    "moderator_dashboard", "moderator_dashboard.php", "moderator_dashboard.html", 
    "administer_dashboard", "administer_dashboard.php", "administer_dashboard.html", 
    "webadmin", "webadmin.php", "webadmin.html", "admin_webadmin", 
    "admin_webadmin.php", "admin_webadmin.html", "administrator_webadmin", 
    "administrator_webadmin.php", "administrator_webadmin.html", 
    "moderator_webadmin", "moderator_webadmin.php", "moderator_webadmin.html", 
    "administer_webadmin", "administer_webadmin.php", "administer_webadmin.html", 
    "admin1/", "admin2/", "admin3/", "admin4/", "admin5/", 
    "usuarios", "usuarios.php", "usuarios.html", "usuario", 
    "usuario.php", "usuario.html", "administrador", "administrador.php", 
    "administrador.html", "moderador", "moderador.php", "moderador.html", 
    "adminis", "adminis.php", "adminis.html", "admins", "admins.php", 
    "admins.html", "administ", "administ.php", "administ.html", 
    "moder", "moder.php", "moder.html", "operador", "operador.php", 
    "operador.html", "sysadm", "sysadm.php", "sysadm.html", 
    "sysadmin", "sysadmin.php", "sysadmin.html", "system_administrator", 
    "system_administrator.php", "system_administrator.html", 
    "system_admin", "system_admin.php", "system_admin.html", 
    "systemoperator", "systemoperator.php", "systemoperator.html", 
    "superuser", "superuser.php", "superuser.html", "supervisor", 
    "supervisor.php", "supervisor.html", "webmaster", "webmaster.php", 
    "webmaster.html", "config", "config.php", "config.html", 
    "configuration", "configuration.php", "configuration.html", 
    "server", "server.php", "server.html", "setup", "setup.php", 
    "setup.html", "install", "install.php", "install.html", 
    "update", "update.php", "update.html", "maintenance", 
    "maintenance.php", "maintenance.html", "phpmyadmin", 
    "phpMyAdmin", "pma", "mysql", "db", "database", "dbadmin", 
    "sql", "sqladmin", "pgadmin", "phppgadmin", "webdb", 
    "web-db", "websql", "web-sql", "server-status", "server-info", 
    "info", "status", "monitor", "monitoring", "log", "logs", 
    "stats", "statistics", "usage", "user", "users", "member", 
    "members", "account", "accounts", "profile", "profiles", 
    "settings", "options", "preferences", "prefs", "control", 
    "manage", "management", "manager", "direct", "directadmin", 
    "cpanel", "whm", "webmin", "virtuozzo", "plesk", "hestia", 
    "vesta", "vestacp", "port", "portal", "myadmin", "my-admin", 
    "ur-admin", "ur-admin.php", "ur-admin.html", "client", 
    "clients", "customer", "customers", "memberadmin", 
    "member-admin", "useradmin", "user-admin", "secure", 
    "security", "private", "priv", "hidden", "hide", "secret", 
    "cgi", "cgi-bin", "cgi-bin/admin", "cgi-bin/administrator", 
    "cgi-bin/login", "cgi-bin/admin.php", "cgi-bin/admin.html", 
    "cgi-bin/administrator.php", "cgi-bin/administrator.html", 
    "cgi-bin/login.php", "cgi-bin/login.html", "bin", "bin/admin", 
    "bin/administrator", "bin/login", "bin/admin.php", "bin/admin.html", 
    "bin/administrator.php", "bin/administrator.html", "bin/login.php", 
    "bin/login.html", "scripts", "scripts/admin", "scripts/administrator", 
    "scripts/login", "scripts/admin.php", "scripts/admin.html", 
    "scripts/administrator.php", "scripts/administrator.html", 
    "scripts/login.php", "scripts/login.html", "tools", "tools/admin", 
    "tools/administrator", "tools/login", "tools/admin.php", 
    "tools/admin.html", "tools/administrator.php", "tools/administrator.html", 
    "tools/login.php", "tools/login.html", "admin-tools", "admin_tools", 
    "administrator-tools", "administrator_tools", "login-tools", 
    "login_tools", "utility", "utilities", "util", "utils", 
    "admin-util", "admin_util", "administrator-util", "administrator_util", 
    "login-util", "login_util", "admin-tool", "admin_tool", 
    "administrator-tool", "administrator_tool", "login-tool", 
    "login_tool", "root", "super", "supervisor", "superuser", 
    "webadmin", "webadmin.php", "webadmin.html", "admin-web", 
    "admin_web", "administrator-web", "administrator_web", 
    "login-web", "login_web", "web-admin", "web_admin", 
    "web-administrator", "web_administrator", "web-login", 
    "web_login", "site", "siteadmin", "site_admin", "siteadmin.php", 
    "siteadmin.html", "siteadministrator", "site_administrator", 
    "siteadministrator.php", "siteadministrator.html", "sitelogin", 
    "site_login", "sitelogin.php", "sitelogin.html", "content", 
    "contentadmin", "content_admin", "contentadmin.php", 
    "contentadmin.html", "contentadministrator", "content_administrator", 
    "contentadministrator.php", "contentadministrator.html", 
    "contentlogin", "content_login", "contentlogin.php", 
    "contentlogin.html", "cms", "cmsadmin", "cms_admin", 
    "cmsadmin.php", "cmsadmin.html", "cmsadministrator", 
    "cms_administrator", "cmsadministrator.php", "cmsadministrator.html", 
    "cmslogin", "cms_login", "cmslogin.php", "cmslogin.html", 
    "backend", "backendadmin", "backend_admin", "backendadmin.php", 
    "backendadmin.html", "backendadministrator", "backend_administrator", 
    "backendadministrator.php", "backendadministrator.html", 
    "backendlogin", "backend_login", "backendlogin.php", 
    "backendlogin.html", "panel", "paneladmin", "panel_admin", 
    "paneladmin.php", "paneladmin.html", "paneladministrator", 
    "panel_administrator", "paneladministrator.php", "paneladministrator.html", 
    "panellogin", "panel_login", "panellogin.php", "panellogin.html", 
    "control", "controladmin", "control_admin", "controladmin.php", 
    "controladmin.html", "controladministrator", "control_administrator", 
    "controladministrator.php", "controladministrator.html", 
    "controllogin", "control_login", "controllogin.php", 
    "controllogin.html", "master", "masteradmin", "master_admin", 
    "masteradmin.php", "masteradmin.html", "masteradministrator", 
    "master_administrator", "masteradministrator.php", "masteradministrator.html", 
    "masterlogin", "master_login", "masterlogin.php", "masterlogin.html", 
    "signin", "signin.php", "signin.html", "sign-in", "sign_in", 
    "signinadmin", "signin_admin", "signinadmin.php", "signinadmin.html", 
    "signinadministrator", "signin_administrator", "signinadministrator.php", 
    "signinadministrator.html", "admin-signin", "admin_signin", 
    "administrator-signin", "administrator_signin", "login-signin", 
    "login_signin", "auth", "auth.php", "auth.html", "authentication", 
    "authentication.php", "authentication.html", "authenticate", 
    "authenticate.php", "authenticate.html", "authorization", 
    "authorization.php", "authorization.html", "authorize", 
    "authorize.php", "authorize.html", "secure", "secure.php", 
    "secure.html", "security", "security.php", "security.html", 
    "adminsecure", "admin_secure", "adminsecure.php", "adminsecure.html", 
    "adminsecurity", "admin_security", "adminsecurity.php", "adminsecurity.html", 
    "adminauth", "admin_auth", "adminauth.php", "adminauth.html", 
    "adminauthentication", "admin_authentication", "adminauthentication.php", 
    "adminauthentication.html", "adminauthorization", "admin_authorization", 
    "adminauthorization.php", "adminauthorization.html", 
    "adminauthorize", "admin_authorize", "adminauthorize.php", "adminauthorize.html"
]

def open_links():
    """Open all provided links automatically"""
    links = [TELEGRAM_ID, WEBSITE, TELEGRAM_CHANNEL]
    for link in links:
        try:
            webbrowser.open(link, new=2)
        except:
            print(f"Failed to open: {link}")

def check_admin_panel(url, path):
    """Check if an admin panel exists at the given path"""
    full_url = urljoin(url, path)
    try:
        response = requests.get(full_url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            print(f"\033[1;32m[FOUND] {full_url}\033[0m")
            return full_url
        elif response.status_code == 403:
            print(f"\033[1;33m[FORBIDDEN] {full_url}\033[0m")
        elif response.status_code == 401:
            print(f"\033[1;33m[UNAUTHORIZED] {full_url}\033[0m")
    except requests.RequestException:
        pass
    return None

def main():
    # Display branding
    print(BRAND)
    print("\033[1;36m" + "="*60 + "\033[0m")
    print(f"\033[1;33mTelegram ID: {TELEGRAM_ID}")
    print(f"My Website: {WEBSITE}")
    print(f"Telegram Channel: {TELEGRAM_CHANNEL}")
    print("\033[1;36m" + "="*60 + "\033[0m")
    
    # Open links automatically
    print("\033[1;35mOpening provided links...\033[0m")
    threading.Thread(target=open_links, daemon=True).start()
    
    # Get target URL from user
    target_url = input("\033[1;34mEnter target URL (e.g., http://example.com): \033[0m").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\033[1;36mScanning {target_url} for admin panels...\033[0m")
    print("\033[1;33mThis may take a while. Press Ctrl+C to stop.\033[0m")
    
    found_panels = []
    
    # Use ThreadPoolExecutor for concurrent requests
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_admin_panel, target_url, path) for path in ADMIN_PATHS]
        for future in futures:
            result = future.result()
            if result:
                found_panels.append(result)
    
    # Display results
    print("\033[1;36m" + "="*60 + "\033[0m")
    if found_panels:
        print("\033[1;32mFound admin panels:\033[0m")
        for panel in found_panels:
            print(f"\033[1;32m- {panel}\033[0m")
    else:
        print("\033[1;31mNo admin panels found.\033[0m")
    
    print("\033[1;36mScan completed. Thank you for using DarkBoss1BD Admin Panel Finder!\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;31mScan interrupted by user. Exiting...\033[0m")
        sys.exit(0)
