import docker
from fivenines_agent.debug import debug, log
previous_stats = {}

def get_docker_client(socket_url=None):
    try:
        if socket_url:
            return docker.DockerClient(base_url=socket_url)
        else:
            return docker.from_env()
    except docker.errors.DockerException as e:
        log(f"Error connecting to Docker daemon: {e}", 'error')
        return None

def docker_containers(socket_url=None):
    client = get_docker_client(socket_url)
    if not client:
        return {}

    containers_data = {}
    try:
        containers = client.containers.list()
        for container in containers:
            stats = container.stats(stream=False, one_shot=True)
            if previous_stats.get(container.id):
                containers_data[container.id] = {
                    'name': container.name,
                    'image': container.image.tags[0] if container.image.tags else container.image.short_id,
                    'status': container.status,
                    'cpu_percent': calculate_cpu_percent(stats, previous_stats[container.id]),
                    'memory_percent': calculate_memory_percent(stats),
                    'memory_usage': calculate_memory_usage(stats),
                    'memory_limit': stats['memory_stats']['limit'],
                    'blkio_stats': stats['blkio_stats'],
                }
                # Networks key is not always defined.
                if stats.get('networks'):
                    containers_data[container.id]['networks'] = stats['networks']

            previous_stats[container.id] = stats
    except Exception as e:
        log(f"Error collecting Docker metrics: {e}", 'error')
        return {}

    return containers_data

def calculate_cpu_percent(stats, previous_stats):
    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - previous_stats['cpu_stats']['cpu_usage']['total_usage']
    system_delta = stats['cpu_stats']['system_cpu_usage'] - previous_stats['cpu_stats']['system_cpu_usage']

    if system_delta > 0.0 and cpu_delta > 0.0:
        return (cpu_delta / system_delta) * 100.0
    return 0.0

# From https://docs.docker.com/reference/cli/docker/container/stats/#description
# On Linux, the Docker CLI reports memory usage by subtracting cache usage from the total memory usage.
# The API does not perform such a calculation but rather provides the total memory usage and the amount
# from the cache so that clients can use the data as needed. The cache usage is defined as the value
# of total_inactive_file field in the memory.stat file on cgroup v1 hosts.
# On Docker 19.03 and older, the cache usage was defined as the value of cache field.
# On cgroup v2 hosts, the cache usage is defined as the value of inactive_file field.

def calculate_memory_percent(stats):
    if stats['memory_stats']['stats'].get('total_inactive_file'):
        return (stats['memory_stats']['usage'] - stats['memory_stats']['stats']['total_inactive_file']) / stats['memory_stats']['limit'] * 100.0
    if stats['memory_stats']['stats'].get('inactive_file'):
        return (stats['memory_stats']['usage'] - stats['memory_stats']['stats']['inactive_file']) / stats['memory_stats']['limit'] * 100.0
    return stats['memory_stats']['usage'] / stats['memory_stats']['limit'] * 100.0

def calculate_memory_usage(stats):
    if stats['memory_stats']['stats'].get('total_inactive_file'):
        return stats['memory_stats']['usage'] - stats['memory_stats']['stats']['total_inactive_file']
    if stats['memory_stats']['stats'].get('inactive_file'):
        return stats['memory_stats']['usage'] - stats['memory_stats']['stats']['inactive_file']
    return stats['memory_stats']['usage']

@debug('docker_metrics')
def docker_metrics(socket_url=None):
    return {
        'containers': docker_containers(socket_url),
    }
