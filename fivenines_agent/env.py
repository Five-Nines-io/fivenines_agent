import os
import platform

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows has no pwd/grp modules
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from fivenines_agent.cli import get_args


def os_family():
    """Return the OS family: 'windows', 'linux', 'darwin', etc."""
    return platform.system().lower()


def is_windows():
    """True when the agent is running on Windows."""
    return os_family() == 'windows'


def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def config_dir():
  env_dir = os.environ.get('CONFIG_DIR')
  if env_dir:
    return env_dir
  if is_windows():
    program_data = os.environ.get('ProgramData', r'C:\ProgramData')
    return os.path.join(program_data, 'fivenines_agent')
  return '/etc/fivenines_agent'

def env_file():
  return os.path.join(config_dir(), '.env')

def dry_run():
  # Check environment variable first
  if os.environ.get('DRY_RUN') == 'true':
    return True
  # Check parsed args
  args = get_args()
  return args is not None and args.dry_run

def log_level():
  if dry_run():
    return 'debug'
  else:
    return os.environ.get('LOG_LEVEL', 'info')


def _windows_user_context(cfg_dir):
    """User context on Windows, where pwd/grp/uid are unavailable."""
    import getpass

    from fivenines_agent.debug import log

    home_dir = os.path.expanduser("~")
    try:
        username = getpass.getuser()
    except Exception:
        username = os.environ.get("USERNAME", "unknown")
    try:
        import ctypes

        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as e:
        log(f"Could not determine Windows admin status: {e}", "error")
        is_admin = False
    return {
        "username": username,
        "is_admin": is_admin,
        "is_root": is_admin,
        "is_user_install": cfg_dir.startswith(home_dir),
        "config_dir": cfg_dir,
        "home_dir": home_dir,
        "os_family": "windows",
    }


def get_user_context(cfg_dir):
    """Get information about the user running the agent."""
    from fivenines_agent.debug import log

    if is_windows():
        return _windows_user_context(cfg_dir)

    try:
        uid = os.getuid()
        euid = os.geteuid()
        gid = os.getgid()

        try:
            username = pwd.getpwuid(uid).pw_name  # type: ignore[union-attr]
        except KeyError:
            username = str(uid)

        try:
            groupname = grp.getgrgid(gid).gr_name  # type: ignore[union-attr]
        except KeyError:
            groupname = str(gid)

        try:
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]  # type: ignore[union-attr]
        except Exception:
            groups = [str(g) for g in os.getgroups()]

        is_user_install = cfg_dir.startswith(os.path.expanduser("~"))

        return {
            "username": username,
            "uid": uid,
            "euid": euid,
            "gid": gid,
            "groupname": groupname,
            "groups": groups,
            "is_root": uid == 0,
            "is_user_install": is_user_install,
            "config_dir": cfg_dir,
            "home_dir": os.path.expanduser("~"),
        }
    except Exception as e:
        log(f"Error getting user context: {e}", "error")
        return {
            "username": "unknown",
            "is_root": False,
            "is_user_install": False,
        }
