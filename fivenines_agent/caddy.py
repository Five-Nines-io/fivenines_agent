import requests

from fivenines_agent.debug import debug, log


# Caddy Admin API metrics collector
# Caddy exposes an admin API (default: localhost:2019) that provides:
# - Server configuration
# - Reverse proxy upstream health
# - Runtime metrics
#
# The admin API must be enabled in Caddy config (enabled by default).
# See: https://caddyserver.com/docs/api

@debug('caddy_metrics')
def caddy_metrics(admin_api_url='http://localhost:2019'):
    """
    Collect metrics from Caddy's admin API.

    Args:
        admin_api_url: URL of Caddy's admin API (default: http://localhost:2019)

    Returns:
        dict: Metrics dictionary or None on error
    """
    try:
        metrics = {}

        # Get Caddy config to extract version and verify connectivity
        config_response = requests.get(f'{admin_api_url}/config/', timeout=5)
        if config_response.status_code != 200:
            log(f"Caddy admin API returned status {config_response.status_code}", 'debug')
            return None

        # Try to get version from /config/
        config = config_response.json() if config_response.text else {}
        metrics['config_loaded'] = config is not None

        # Get reverse proxy upstreams health if available
        try:
            upstreams_response = requests.get(f'{admin_api_url}/reverse_proxy/upstreams', timeout=5)
            if upstreams_response.status_code == 200:
                upstreams = upstreams_response.json() or []
                metrics['upstreams'] = []
                healthy_count = 0
                unhealthy_count = 0

                for upstream in upstreams:
                    address = upstream.get('address', 'unknown')
                    num_requests = upstream.get('num_requests', 0)
                    fails = upstream.get('fails', 0)
                    healthy = upstream.get('healthy', True)

                    if healthy:
                        healthy_count += 1
                    else:
                        unhealthy_count += 1

                    metrics['upstreams'].append({
                        'address': address,
                        'num_requests': num_requests,
                        'fails': fails,
                        'healthy': healthy
                    })

                metrics['upstreams_total'] = len(upstreams)
                metrics['upstreams_healthy'] = healthy_count
                metrics['upstreams_unhealthy'] = unhealthy_count
        except Exception as e:
            log(f"Could not fetch Caddy upstreams: {e}", 'debug')
            # Upstreams endpoint may not exist if no reverse proxy is configured
            metrics['upstreams_total'] = 0
            metrics['upstreams_healthy'] = 0
            metrics['upstreams_unhealthy'] = 0

        # Get PKI information if available (for certificate management)
        try:
            pki_response = requests.get(f'{admin_api_url}/pki/ca/local', timeout=5)
            if pki_response.status_code == 200:
                pki_info = pki_response.json() or {}
                metrics['pki_enabled'] = True
                metrics['pki_root_cn'] = pki_info.get('root_common_name', '')
                metrics['pki_intermediate_cn'] = pki_info.get('intermediate_common_name', '')
            else:
                metrics['pki_enabled'] = False
        except Exception:
            metrics['pki_enabled'] = False

        # Count apps configured (servers, tls, etc.)
        if config:
            apps = config.get('apps', {})
            metrics['apps_configured'] = list(apps.keys()) if apps else []

            # Count HTTP servers
            http_app = apps.get('http', {})
            servers = http_app.get('servers', {})
            metrics['http_servers_count'] = len(servers)

            # Count TLS automation policies
            tls_app = apps.get('tls', {})
            automation = tls_app.get('automation', {})
            policies = automation.get('policies', [])
            metrics['tls_automation_policies'] = len(policies) if policies else 0

        return metrics

    except requests.exceptions.ConnectionError:
        log("Cannot connect to Caddy admin API", 'debug')
        return None
    except Exception as e:
        log(f"Error collecting Caddy metrics: {e}", 'error')
        return None
