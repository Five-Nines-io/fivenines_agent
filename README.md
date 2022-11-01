# Five nines client

This client collects server metrics and send it to the [Five nines](https://five-nines.io) API.

## Setup

1 - Clone this repository to the `/opt` folder
```
cd /opt && sudo git clone git@github.com:Five-Nines-io/Five-nines-client.git five_nines_client
```

2 - Install dependencies
```
sudo python3 -m venv five_nines_client/venv && sudo five_nines_client/venv/bin/pip3 install -r requirements.txt
```

2 - Copy the service file

```
sudo cp /opt/five_nines_client/five-nines-client.service /etc/systemd/system/
```

3 - Reload the service files to include the five-nines-client service

```
sudo systemctl daemon-reload
```

4 - Enable five-nines-client service on every reboot
```
sudo systemctl enable five-nines-client.service
```

5 - Start the five-nines-client
```
sudo systemctl start five-nines-client
```

## Update

1 - Fetch the latest client version
```
cd /opt/five_nines_client/ && sudo git pull
```

2 - Copy the service file

```
sudo cp /opt/five-nines-client.service /etc/systemd/system/
```

3 - Reload the service files to update the service

```
sudo systemctl daemon-reload
```

4 - Restart the service
```
sudo systemctl restart five-nines-client
```

## Contribute

Feel free to open a PR if you see potential bugfixes or improvements.

## Contact

You can shoot me an email at: [sebastien@five-nines.io](mailto:sebastien@five-nines.io)
