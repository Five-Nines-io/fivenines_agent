import docker

def get_docker_client(socket_url=None):
    try:
        if socket_url:
            return docker.DockerClient(base_url=socket_url)
        else:
            return docker.from_env()
    except docker.errors.DockerException as e:
        print("Error connecting to Docker daemon.")
        print(e)
        return None

def docker_containers(socket_url=None):
    client = get_docker_client(socket_url)
    if not client:
        return {}

    containers_data = {}
    try:
        containers = client.containers.list()
        for container in containers:
            stats = container.stats(stream=False)
            containers_data[container.id] = {
                'name': container.name,
                'image': container.image.tags[0],
                'status': container.status,
                'cpu_percent': calculate_cpu_percent(stats),
                'memory_usage': stats['memory_stats']['usage'],
                'memory_limit': stats['memory_stats']['limit'],
                'networks': stats['networks'],
                'blkio_stats': stats['blkio_stats'],
            }
    except Exception as e:
        print(f"Error collecting Docker metrics: {e}")
        return {}

    return containers_data

def calculate_cpu_percent(stats):
    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                stats['precpu_stats']['cpu_usage']['total_usage']
    system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                   stats['precpu_stats']['system_cpu_usage']

    if system_delta > 0.0 and cpu_delta > 0.0:
        return (cpu_delta / system_delta) * 100.0
    return 0.0

def docker_metrics(socket_url=None):
    return {
        'containers': docker_containers(socket_url),
    }
