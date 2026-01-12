import re
import requests

from fivenines_agent.debug import debug, log


def _parse_prometheus_metric(metrics_text, metric_name):
    """Parse a simple Prometheus metric value from metrics text."""
    # Match lines like: metric_name 123.45 or metric_name{labels} 123.45
    pattern = rf'^{re.escape(metric_name)}(?:\{{[^}}]*\}})?\s+([\d.e+-]+)'
    for line in metrics_text.split('\n'):
        match = re.match(pattern, line)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
    return None


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

        # Get process metrics from Prometheus endpoint
        try:
            prom_response = requests.get(f'{admin_api_url}/metrics', timeout=5)
            if prom_response.status_code == 200:
                prom_text = prom_response.text

                # Process metrics
                cpu_seconds = _parse_prometheus_metric(prom_text, 'process_cpu_seconds_total')
                if cpu_seconds is not None:
                    metrics['process_cpu_seconds'] = cpu_seconds

                memory_bytes = _parse_prometheus_metric(prom_text, 'process_resident_memory_bytes')
                if memory_bytes is not None:
                    metrics['process_memory_bytes'] = int(memory_bytes)

                open_fds = _parse_prometheus_metric(prom_text, 'process_open_fds')
                if open_fds is not None:
                    metrics['process_open_fds'] = int(open_fds)

                goroutines = _parse_prometheus_metric(prom_text, 'go_goroutines')
                if goroutines is not None:
                    metrics['goroutines'] = int(goroutines)

                # Network traffic through Caddy
                net_rx = _parse_prometheus_metric(prom_text, 'process_network_receive_bytes_total')
                if net_rx is not None:
                    metrics['network_receive_bytes'] = int(net_rx)

                net_tx = _parse_prometheus_metric(prom_text, 'process_network_transmit_bytes_total')
                if net_tx is not None:
                    metrics['network_transmit_bytes'] = int(net_tx)
        except Exception as e:
            log(f"Could not fetch Caddy Prometheus metrics: {e}", 'debug')

        return metrics

    except requests.exceptions.ConnectionError:
        log("Cannot connect to Caddy admin API", 'debug')
        return None
    except Exception as e:
        log(f"Error collecting Caddy metrics: {e}", 'error')
        return None
