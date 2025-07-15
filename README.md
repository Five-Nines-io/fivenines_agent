# fivenines agent

This agent collects server metrics from the monitored host and sends it to the [fivenines](https://fivenines.io) API.

## Setup

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN
```

## Update

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_update.sh && sudo bash fivenines_update.sh
```

## Remove

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_uninstall.sh && sudo bash fivenines_uninstall.sh
```

## Debug

If you need to debug the agent collected data, you can run the following command:

```bash
/opt/fivenines/fivenines_agent --dry-run
```

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
