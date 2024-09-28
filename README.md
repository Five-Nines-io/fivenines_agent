# fivenines agent

This agent collects server metrics from the monitored host and send it to the [fivenines](https://fivenines.io) API.

## Setup

```bash
wget -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN
```

## Update

```bash
wget -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_update.sh && sudo bash fivenines_update.sh
```

## Known issues

After a distribution upgrade, the agent may not start because of a [known pipx issue](https://github.com/pypa/pipx/issues/278).

To fix it, you can reinstall packages managed by pipx:

```bash
sudo su - fivenines -s /bin/bash -c 'python3 -m pipx reinstall-all'
```

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
