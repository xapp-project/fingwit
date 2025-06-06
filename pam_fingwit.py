#!/usr/bin/python3
"""
pam_fingwit - Smart fingerprint PAM module
Following the same D-Bus pattern as fprintd's official PAM module
"""

import os
import sys
import threading
import time
import syslog
import gi
gi.require_version('Gio', '2.0')
gi.require_version('GLib', '2.0')
from gi.repository import Gio, GLib

def pam_sm_authenticate(pamh, flags, argv):
    """Main PAM authentication function"""
    
    # Initialize syslog like fprintd does
    syslog.openlog("pam_fingwit", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    
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
        
        # Check all our detection functions
        ssh_session = is_ssh_session()
        login_session = is_login_session()
        encrypted_home = has_encrypted_home(user)
        fprintd_available = is_fprintd_available()
        has_prints = has_fingerprints(user)
        
        if debug:
            syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: ssh={ssh_session}, login={login_session}, encrypted={encrypted_home}")
            syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: fprintd_avail={fprintd_available}, has_prints={has_prints}")
        
        # Skip fingerprint auth for SSH sessions
        if ssh_session:
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: SKIPPING - SSH session detected")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if this is a login session (where encrypted home matters)
        if login_session and encrypted_home:
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: SKIPPING - encrypted home for login session")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if fprintd is available and running
        if not fprintd_available:
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: SKIPPING - fprintd not available")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        # Check if user has enrolled fingerprints
        if not has_prints:
            if debug:
                syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: SKIPPING - no fingerprints for {user}")
            return pamh.PAM_AUTHINFO_UNAVAIL
        
        if debug:
            syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: PROCEEDING with fingerprint authentication")
        
        # Proceed with fingerprint authentication using proper D-Bus
        return do_fingerprint_auth_dbus(pamh, user, max_tries, timeout, debug)
        
    except Exception as e:
        # Log error and fall back to next auth method
        pamh.conversation(pamh.PAM_ERROR_MSG, f"fingwit EXCEPTION: {e}")
        return pamh.PAM_AUTHINFO_UNAVAIL

def do_fingerprint_auth_dbus(pamh, user, max_tries=3, timeout=30, debug=False):
    """Perform fingerprint authentication using D-Bus like official fprintd PAM module"""
    
    class FingerprintAuth:
        def __init__(self, pamh, user, debug=False):
            self.pamh = pamh
            self.user = user
            self.debug = debug
            self.result = None
            self.finished = False
            self.loop = None
            self.device = None
            self.bus = None
            self.device_path = None
            
        def authenticate(self, timeout_seconds):
            """Main authentication method - mirrors fprintd PAM module logic"""
            try:
                # Get system bus
                self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
                
                # Get fingerprint manager
                manager = Gio.DBusProxy.new_sync(
                    self.bus, 
                    Gio.DBusProxyFlags.NONE, 
                    None,
                    'net.reactivated.Fprint',
                    '/net/reactivated/Fprint/Manager',
                    'net.reactivated.Fprint.Manager',
                    None
                )
                
                # Get default device (like fprintd PAM module does)
                try:
                    default_device_result = manager.call_sync(
                        'GetDefaultDevice', 
                        None, 
                        Gio.DBusCallFlags.NONE, 
                        -1, 
                        None
                    )
                    self.device_path = default_device_result.unpack()[0]
                except:
                    # Fallback: get first available device
                    devices_result = manager.call_sync(
                        'GetDevices', 
                        None, 
                        Gio.DBusCallFlags.NONE, 
                        -1, 
                        None
                    )
                    device_paths = devices_result.unpack()[0]
                    if not device_paths:
                        self.result = 'NO_DEVICE'
                        return
                    self.device_path = device_paths[0]
                
                # Create device proxy
                self.device = Gio.DBusProxy.new_sync(
                    self.bus, 
                    Gio.DBusProxyFlags.NONE, 
                    None,
                    'net.reactivated.Fprint',
                    self.device_path,
                    'net.reactivated.Fprint.Device',
                    None
                )
                
                # Connect to signals BEFORE claiming device
                self.device.connect('g-signal', self._on_signal)
                
                # Claim device for this user
                self.device.call_sync(
                    'Claim', 
                    GLib.Variant('(s)', (self.user,)), 
                    Gio.DBusCallFlags.NONE, 
                    -1, 
                    None
                )
                
                if self.debug:
                    syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: Device claimed for user {self.user}")
                
                # Start verification with 'any' finger (like fprintd PAM module)
                self.device.call_sync(
                    'VerifyStart', 
                    GLib.Variant('(s)', ('any',)), 
                    Gio.DBusCallFlags.NONE, 
                    -1, 
                    None
                )
                
                if self.debug:
                    syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: Verification started")
                
                # Create and run main loop with timeout
                self.loop = GLib.MainLoop()
                GLib.timeout_add_seconds(timeout_seconds, self._on_timeout)
                
                # This blocks until verification completes or times out
                self.loop.run()
                
                return self.result
                
            except Exception as e:
                if self.debug:
                    syslog.syslog(syslog.LOG_ERR, f"pam_fingwit: D-Bus auth error: {e}")
                self.result = f'ERROR: {e}'
                return self.result
            finally:
                self._cleanup()
                
        def _on_signal(self, proxy, sender_name, signal_name, parameters):
            """Handle D-Bus signals from fingerprint device"""
            if signal_name == 'VerifyStatus':
                status, done = parameters.unpack()
                
                if self.debug:
                    syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: VerifyStatus: {status}, done: {done}")
                
                if status == 'verify-match':
                    self.result = 'SUCCESS'
                    self._quit_loop()
                elif status == 'verify-no-match':
                    self.result = 'NO_MATCH'
                    # Don't quit yet - let it try again or timeout
                elif status == 'verify-swipe-too-short':
                    self.result = 'SWIPE_TOO_SHORT'
                    # Don't quit yet
                elif status == 'verify-finger-not-centered':
                    self.result = 'NOT_CENTERED'
                    # Don't quit yet
                elif status == 'verify-remove-and-retry':
                    self.result = 'REMOVE_RETRY'
                    # Don't quit yet
                elif status.startswith('verify-'):
                    # Other verify statuses - continue
                    pass
                else:
                    # Unknown status
                    if self.debug:
                        syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: Unknown verify status: {status}")
                
                # If done flag is set, finish verification
                if done:
                    if not self.result or self.result in ['NO_MATCH', 'SWIPE_TOO_SHORT', 'NOT_CENTERED', 'REMOVE_RETRY']:
                        self.result = 'FAILED'
                    self._quit_loop()
                    
        def _on_timeout(self):
            """Handle timeout"""
            if not self.finished:
                if self.debug:
                    syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: Authentication timed out")
                self.result = 'TIMEOUT'
                self._quit_loop()
            return False  # Don't repeat timeout
            
        def _quit_loop(self):
            """Quit the main loop"""
            self.finished = True
            if self.loop and self.loop.is_running():
                self.loop.quit()
                
        def _cleanup(self):
            """Clean up D-Bus resources"""
            try:
                if self.device and self.device_path:
                    # Stop verification
                    try:
                        self.device.call_sync(
                            'VerifyStop', 
                            None, 
                            Gio.DBusCallFlags.NONE, 
                            1000, 
                            None
                        )
                    except:
                        pass
                    
                    # Release device
                    try:
                        self.device.call_sync(
                            'Release', 
                            None, 
                            Gio.DBusCallFlags.NONE, 
                            1000, 
                            None
                        )
                    except:
                        pass
                        
                    if self.debug:
                        syslog.syslog(syslog.LOG_DEBUG, "pam_fingwit: Device released")
                        
            except Exception as e:
                if self.debug:
                    syslog.syslog(syslog.LOG_ERR, f"pam_fingwit: Cleanup error: {e}")
    
    # Prompt user
    pamh.conversation(pamh.PAM_TEXT_INFO, "Place your finger on the fingerprint reader")
    
    for attempt in range(max_tries):
        if debug:
            syslog.syslog(syslog.LOG_DEBUG, f"pam_fingwit: attempt {attempt + 1}/{max_tries}")
        
        # Create authenticator and run
        auth = FingerprintAuth(pamh, user, debug)
        result = auth.authenticate(timeout)
        
        if result == 'SUCCESS':
            pamh.conversation(pamh.PAM_TEXT_INFO, "Fingerprint authentication successful")
            return pamh.PAM_SUCCESS
        elif result == 'NO_DEVICE':
            pamh.conversation(pamh.PAM_ERROR_MSG, "No fingerprint device available")
            return pamh.PAM_AUTHINFO_UNAVAIL
        elif result == 'TIMEOUT':
            pamh.conversation(pamh.PAM_ERROR_MSG, f"Fingerprint authentication timed out after {timeout}s")
            break
        elif result and result.startswith('ERROR'):
            pamh.conversation(pamh.PAM_ERROR_MSG, f"Fingerprint authentication error: {result}")
            return pamh.PAM_AUTH_ERR
        elif attempt < max_tries - 1:
            # Provide specific feedback based on result
            if result == 'SWIPE_TOO_SHORT':
                pamh.conversation(pamh.PAM_ERROR_MSG, "Swipe was too short, try again")
            elif result == 'NOT_CENTERED':
                pamh.conversation(pamh.PAM_ERROR_MSG, "Finger not centered, try again")
            elif result == 'REMOVE_RETRY':
                pamh.conversation(pamh.PAM_ERROR_MSG, "Remove finger and try again")
            else:
                pamh.conversation(pamh.PAM_ERROR_MSG, "Try again...")
    
    pamh.conversation(pamh.PAM_ERROR_MSG, "Fingerprint authentication failed")
    return pamh.PAM_AUTH_ERR

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
    """Check if user has enrolled fingerprints via D-Bus"""
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
        
        # Try to get default device first
        try:
            device_result = manager.call_sync('GetDefaultDevice', None, Gio.DBusCallFlags.NONE, 1000, None)
            device_path = device_result.unpack()[0]
        except:
            # Fallback to first device
            devices = manager.call_sync('GetDevices', None, Gio.DBusCallFlags.NONE, 1000, None)
            device_paths = devices.unpack()[0]
            if not device_paths:
                return False
            device_path = device_paths[0]
        
        # Get device proxy
        device = Gio.DBusProxy.new_sync(
            bus,
            Gio.DBusProxyFlags.NONE,
            None,
            'net.reactivated.Fprint',
            device_path,
            'net.reactivated.Fprint.Device',
            None
        )
        
        # List enrolled fingers for user
        fingers = device.call_sync(
            'ListEnrolledFingers', 
            GLib.Variant('(s)', (user,)), 
            Gio.DBusCallFlags.NONE, 
            2000, 
            None
        )
        return len(fingers.unpack()[0]) > 0
        
    except:
        return False

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
                # Log to both stderr and syslog like the C wrapper would
                print(f"pam_fingwit: {message}", file=sys.stderr)
                if msg_type == self.PAM_ERROR_MSG:
                    syslog.syslog(syslog.LOG_ERR, f"pam_fingwit: {message}")
                else:
                    syslog.syslog(syslog.LOG_INFO, f"pam_fingwit: {message}")
        
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