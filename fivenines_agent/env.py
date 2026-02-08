import grp
import os
import pwd

from fivenines_agent.cli import get_args


def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def config_dir():
  return os.environ.get('CONFIG_DIR', '/etc/fivenines_agent')

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


def get_user_context(cfg_dir):
    """Get information about the user running the agent."""
    from fivenines_agent.debug import log

    try:
        uid = os.getuid()
        euid = os.geteuid()
        gid = os.getgid()

        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)

        try:
            groupname = grp.getgrgid(gid).gr_name
        except KeyError:
            groupname = str(gid)

        try:
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
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
