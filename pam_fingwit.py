#!/usr/bin/python3
import gi
import json
import os
import PAM
import subprocess
import sys
import syslog
gi.require_version('Gio', '2.0')
gi.require_version('GLib', '2.0')
from gi.repository import Gio, GLib

def pam_sm_authenticate(pamh, flags, argv):
    """Main PAM authentication function"""
    
    # Initialize syslog like fprintd does
    syslog.openlog("pam_fingwit", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    
    try:
        settings = Gio.Settings(schema_id="org.x.fingwit")

        # Parse PAM module arguments
        debug = False
        
        for arg in argv:
            if arg == 'debug':
                debug = True

        # Get username from PAM
        user = pamh.get_user()
        if not user:
            return PAM.PAM_IGNORE
                
        # Skip fingerprint auth for SSH sessions
        if is_ssh_session():
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: PAM_AUTHINFO_UNAVAIL (SSH session)")
            return PAM.PAM_AUTHINFO_UNAVAIL
        
        if user_has_sessions(user):
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: PAM_IGNORE (session already exists)")
            return PAM.PAM_IGNORE

        # Check if this is a login session
        if is_login_session():
            if not settings.get_boolean("login-enabled"):
                if debug:
                    syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: PAM_AUTHINFO_UNAVAIL (login, password required)")
                return PAM.PAM_AUTHINFO_UNAVAIL
            
            if has_encrypted_home(user):
                if debug:
                    syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: PAM_AUTHINFO_UNAVAIL (login, encrypted home)")
                return PAM.PAM_AUTHINFO_UNAVAIL
    
        # Everything looks fine, proceed to the next PAM module        
        if debug:
            syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: returning PAM_IGNORE")
        return PAM.PAM_IGNORE
        
    except Exception as e:
        # Log error and fall back to next auth method
        if debug:
            syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: EXCEPTION: {e}")
        return PAM.PAM_IGNORE


def is_login_session():
    """Check if this is an initial login session (where home decryption matters)"""
    
    # Method 1: Check PAM service name (most reliable)
    pam_service = os.environ.get('PAM_SERVICE')
    if pam_service:
        # Only these services require home directory decryption
        login_services = ['lightdm', 'gdm', 'kdm', 'mdm', 'sddm', 'login']
        if pam_service in login_services:
            return True
    
    # Method 2: Check IMMEDIATE parent (not whole tree)
    # If the direct parent is a display manager, it's probably initial login
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/comm', 'r') as f:
            parent_name = f.read().strip()
            
        # Direct parent is a display manager = initial login
        if parent_name in ['lightdm', 'gdm', 'kdm', 'mdm', 'sddm', 'login']:
            return True
            
    except:
        pass
    
    return False

def is_ssh_session():
    """Check if this is an SSH session"""
    # Check various SSH indicators
    ssh_indicators = [
        os.environ.get('SSH_CLIENT'),
        os.environ.get('SSH_CONNECTION'), 
        os.environ.get('SSH_TTY'),
        os.environ.get('SSH_ORIGINAL_COMMAND')
    ]
    
    if any(ssh_indicators):
        return True
    
    # Check if parent process is sshd
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/comm', 'r') as f:
            parent_name = f.read().strip()
            if parent_name == 'sshd':
                return True
    except:
        pass
        
    return False

def user_has_sessions(user):
    try:
        # Get user sessions from loginctl
        result = subprocess.run(['loginctl', 'list-sessions', '--output=json'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            sessions = json.loads(result.stdout)
            for session in sessions:
                if session.get('user') == user:
                    return True
    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        pass
    return False

def has_encrypted_home(user):
    """Check if user has an encrypted home directory"""
    ecryptfs_paths = [
        f"/home/.ecryptfs/{user}",
        f"/home/{user}/.ecryptfs",
        f"/home/{user}/.Private"
    ]
    
    for path in ecryptfs_paths:
        if os.path.exists(path):
            return True
    return False

# Required PAM module functions
def pam_sm_setcred(pamh, flags, argv):
    """Set credentials (not needed for authentication)"""
    return PAM.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    """Account management (not needed)"""
    return PAM.PAM_SUCCESS

if __name__ == "__main__":
    # Check if we're being called by PAM C wrapper
    if len(sys.argv) >= 3 and not sys.argv[1].startswith('TEST'):
        # Called by C wrapper: python3 script.py user service [pam_args...]
        user = sys.argv[1]
        service = sys.argv[2]
        pam_args = sys.argv[3:] if len(sys.argv) > 3 else []
        
        # Set environment for consistency
        os.environ['PAM_USER'] = user
        os.environ['PAM_SERVICE'] = service
        
        # Create a simple PAM handle wrapper
        class CLIPAMHandle:        
            def get_user(self):
                return user
        
        # Run authentication and exit with appropriate code
        result = pam_sm_authenticate(CLIPAMHandle(), 0, pam_args)
        sys.exit(result)
    
    else:
        # Original test code when run directly or with TEST argument
        import pwd
        
        class MockPAM:            
            def get_user(self):
                return pwd.getpwuid(os.getuid()).pw_name
        
        def run_test(test_name, **env_vars):
            """Run a PAM authentication test with given environment variables"""
            print(f"\n=== {test_name} ===")
            
            # Set up environment
            original_env = {}
            for key, value in env_vars.items():
                original_env[key] = os.environ.get(key)
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]
            
            # Run test
            mock_pam = MockPAM()
            result = pam_sm_authenticate(mock_pam, 0, ['debug'])
            print(f"Result: {result}")
            
            # Restore environment
            for key, original_value in original_env.items():
                if original_value is not None:
                    os.environ[key] = original_value
                elif key in os.environ:
                    del os.environ[key]
            
            return result
        
        # Display initial module info
        print("Testing pam_fingwit module...")
        user = pwd.getpwuid(os.getuid()).pw_name
        print(f"User: {user}")
        print(f"SSH session: {is_ssh_session()}")
        print(f"Login session: {is_login_session()}")
        print(f"Encrypted home: {has_encrypted_home(user)}")
        print(f"Has sessions: {user_has_sessions(user)}")
        
        # Run all tests
        run_test("TEST 1: Current context (desktop session)")
        run_test("TEST 2: Simulated LOGIN session (lightdm)", PAM_SERVICE='lightdm')
        run_test("TEST 3: Simulated SUDO session", PAM_SERVICE='sudo')
        run_test("TEST 4: Simulated SSH session", PAM_SERVICE='sudo', SSH_CLIENT='127.0.0.1 12345 22')
        
        print("\n=== SUMMARY ===")
        print("25 = IGNORE (move towards fprintd)")
        print("9 = AUTHINFO_UNAVAIL (skip fprintd)")
        print("")
