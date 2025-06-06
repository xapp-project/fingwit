#!/usr/bin/python3
"""
pam_fingwit - Smart fingerprint PAM module
Automatically detects encrypted home directories and skips fingerprint auth when needed.
"""

import os
import sys
import subprocess
import gi
gi.require_version('Gio', '2.0')
from gi.repository import Gio, GLib

def pam_sm_authenticate(pamh, flags, argv):
    """Main PAM authentication function"""
    
    try:
        # Parse PAM module arguments
        max_tries = 3  # default
        timeout = 30   # default
        debug = False
        
        for arg in argv:
            if arg.startswith('max-tries='):
                max_tries = int(arg.split('=')[1])
            elif arg.startswith('timeout='):
                timeout = int(arg.split('=')[1])
            elif arg == 'debug':
                debug = True
        
        # Get username from PAM
        user = pamh.get_user()
        if not user:
            return pamh.PAM_USER_UNKNOWN
        
        # Skip fingerprint auth for SSH sessions
        if is_ssh_session():
            if debug:
                pamh.conversation(pamh.PAM_TEXT_INFO, "fingwit: skipping SSH session")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if this is a login session (where encrypted home matters)
        if is_login_session() and has_encrypted_home(user):
            if debug:
                pamh.conversation(pamh.PAM_TEXT_INFO, f"fingwit: skipping encrypted home for login session")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if fprintd is available and running
        if not is_fprintd_available():
            if debug:
                pamh.conversation(pamh.PAM_TEXT_INFO, "fingwit: fprintd not available")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if user has enrolled fingerprints
        if not has_fingerprints(user):
            if debug:
                pamh.conversation(pamh.PAM_TEXT_INFO, f"fingwit: no fingerprints for {user}")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Proceed with fingerprint authentication
        return do_fingerprint_auth(pamh, user, max_tries, timeout, debug)
        
    except Exception as e:
        # Log error and fall back to next auth method
        pamh.conversation(pamh.PAM_ERROR_MSG, f"fingwit error: {e}")
        return pamh.PAM_AUTHINFO_UNAVAIL

def is_login_session():
    """Check if this is an initial login session (where home decryption matters)"""
    
    # Method 1: Check PAM service name (most reliable)
    pam_service = os.environ.get('PAM_SERVICE')
    if pam_service:
        # Only these services require home directory decryption
        login_services = ['lightdm', 'gdm', 'sddm', 'login']
        if pam_service in login_services:
            return True
    
    # Method 2: Check IMMEDIATE parent (not whole tree)
    # If the direct parent is a display manager, it's probably initial login
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/comm', 'r') as f:
            parent_name = f.read().strip()
            
        # Direct parent is a display manager = initial login
        if parent_name in ['lightdm', 'gdm', 'gdm-session-wor', 'sddm', 'login']:
            return True
            
    except:
        pass
    
    # Default: assume NOT a login session
    # Screen unlocker, sudo, etc. will have session managers as parents, not DMs
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
    
    # Check if stdin is not a tty (non-interactive)
    if not os.isatty(0):
        return True
        
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

def is_fprintd_available():
    """Check if fprintd service is available via D-Bus"""
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        manager = Gio.DBusProxy.new_sync(
            bus,
            Gio.DBusProxyFlags.NONE,
            None,
            'net.reactivated.Fprint',
            '/net/reactivated/Fprint/Manager',
            'net.reactivated.Fprint.Manager',
            None
        )
        # Try to get devices to verify service is working
        devices = manager.call_sync('GetDevices', None, Gio.DBusCallFlags.NONE, 1000, None)
        return len(devices.unpack()[0]) > 0
    except:
        return False

def has_fingerprints(user):
    """Check if user has enrolled fingerprints"""
    try:
        result = subprocess.run(
            ['fprintd-list', user],
            capture_output=True,
            text=True,
            timeout=5
        )
        # fprintd-list returns 0 if user has prints, non-zero if not
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def do_fingerprint_auth(pamh, user, max_tries=3, timeout=30, debug=False):
    """Perform fingerprint authentication using D-Bus"""
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        
        # Get first available device
        manager = Gio.DBusProxy.new_sync(
            bus, Gio.DBusProxyFlags.NONE, None,
            'net.reactivated.Fprint',
            '/net/reactivated/Fprint/Manager',
            'net.reactivated.Fprint.Manager',
            None
        )
        
        devices = manager.call_sync('GetDevices', None, Gio.DBusCallFlags.NONE, -1, None)
        device_paths = devices.unpack()[0]
        
        if not device_paths:
            return pamh.PAM_AUTHINFO_UNAVAIL
            
        # Use first device for verification
        device = Gio.DBusProxy.new_sync(
            bus, Gio.DBusProxyFlags.NONE, None,
            'net.reactivated.Fprint',
            device_paths[0],
            'net.reactivated.Fprint.Device',
            None
        )
        
        # Prompt user
        pamh.conversation(pamh.PAM_TEXT_INFO, "Place your finger on the fingerprint reader")
        
        # For now, use fprintd-verify with the configured timeout
        # In a full implementation, you'd handle D-Bus signals properly
        for attempt in range(max_tries):
            if debug:
                pamh.conversation(pamh.PAM_TEXT_INFO, f"fingwit: attempt {attempt + 1}/{max_tries}")
            
            try:
                result = subprocess.run(
                    ['fprintd-verify', user],
                    capture_output=True,
                    timeout=timeout
                )
                
                if result.returncode == 0:
                    pamh.conversation(pamh.PAM_TEXT_INFO, "Fingerprint verification successful")
                    return pamh.PAM_SUCCESS
                elif attempt < max_tries - 1:
                    pamh.conversation(pamh.PAM_ERROR_MSG, "Try again...")
                    
            except subprocess.TimeoutExpired:
                if debug:
                    pamh.conversation(pamh.PAM_ERROR_MSG, f"fingwit: timeout after {timeout}s")
                break
        
        pamh.conversation(pamh.PAM_ERROR_MSG, "Fingerprint verification failed")
        return pamh.PAM_AUTH_ERR
            
    except Exception as e:
        if debug:
            pamh.conversation(pamh.PAM_ERROR_MSG, f"Fingerprint auth error: {e}")
        return pamh.PAM_AUTH_ERR

# Required PAM module functions
def pam_sm_setcred(pamh, flags, argv):
    """Set credentials (not needed for authentication)"""
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    """Account management (not needed)"""
    return pamh.PAM_SUCCESS

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
            PAM_SUCCESS = 0
            PAM_AUTH_ERR = 7
            PAM_USER_UNKNOWN = 10
            PAM_AUTHINFO_UNAVAIL = 9
            PAM_TEXT_INFO = 3
            PAM_ERROR_MSG = 4
            
            def get_user(self):
                return user
                
            def conversation(self, msg_type, message):
                # Log to stderr so it appears in PAM logs
                print(f"pam_fingwit: {message}", file=sys.stderr)
        
        # Run authentication and exit with appropriate code
        result = pam_sm_authenticate(CLIPAMHandle(), 0, pam_args)
        sys.exit(result)
    
    else:
        # Original test code when run directly or with TEST argument
        import pwd
        
        class MockPAM:
            PAM_SUCCESS = 0
            PAM_AUTH_ERR = 7
            PAM_USER_UNKNOWN = 10
            PAM_AUTHINFO_UNAVAIL = 9
            PAM_TEXT_INFO = 3
            PAM_ERROR_MSG = 4
            
            def get_user(self):
                return pwd.getpwuid(os.getuid()).pw_name
                
            def conversation(self, msg_type, message):
                print(f"PAM {msg_type}: {message}")
        
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
            result = pam_sm_authenticate(mock_pam, 0, ['debug', 'max-tries=1', 'timeout=10'])
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
        print(f"fprintd available: {is_fprintd_available()}")
        print(f"Has fingerprints: {has_fingerprints(user)}")
        
        # Run all tests
        run_test("TEST 1: Current context (desktop session)")
        run_test("TEST 2: Simulated LOGIN session (lightdm)", PAM_SERVICE='lightdm')
        run_test("TEST 3: Simulated SUDO session", PAM_SERVICE='sudo')
        run_test("TEST 4: Simulated SSH session", PAM_SERVICE='sudo', SSH_CLIENT='127.0.0.1 12345 22')
        
        print("\n=== SUMMARY ===")
        print("0 = SUCCESS (fingerprint auth succeeded)")
        print("7 = AUTH_ERR (fingerprint auth failed)")  
        print("9 = AUTHINFO_UNAVAIL (skipped fingerprint)")
        print("")
        print("Expected results for user with encrypted home:")
        print("- Desktop context: 0 (allow fingerprint)")
        print("- Login (lightdm): 9 (skip fingerprint, need password for home decryption)")
        print("- Sudo: 0 (allow fingerprint, home already decrypted)")
        print("- SSH: 9 (skip fingerprint, avoid interference)")