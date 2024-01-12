# Five nines client

This client collects server metrics and send it to the [Five nines](https://fivenines.io) API.

## Setup

1 - Clone this repository to the `/opt` folder
```
sudo git clone https://github.com/Five-Nines-io/Five-nines-client.git /opt/five_nines_client
```

2 - Setup the client
```
cd /opt/five_nines_client && ./setup.sh TOKEN
```

3 - Check that the client is running
```
sudo systemctl status five-nines-client
```

## Update

1 - Run the updater
```
cd /opt/five_nines_client && ./update.sh
```

2 - Check that the client is running
```
sudo systemctl status five-nines-client
```

## Contribute

Feel free to open a PR if you see potential bugfixes or improvements.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
