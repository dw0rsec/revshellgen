# revshellgen

This Python script generates reverse shells for various languages and platforms. It offers the flexibility to choose different shell types, encode them in base64 or urlencode format, and optionally start a listener to catch incoming connections.

## Prerequisites:

- Python 3.x
- Netcat (nc) for starting a listener

## Usage:

**1. Clone the repository:**

```shell
git clone https://github.com/yourusername/revshellgen.git
```

**2. Navigate to the project directory:**

```shell
cd revshellgen
```

**3. Run the script:**

```shell
python3 ./revshellgen.py -t bash -i <YOUR_IP_ADDRESS> -p <PORT_NUMBER>
```

## Command-line Options:

`-t, --type SHELL`: Select a reverse shell type.

`-i, --ip ADDRESS`: The IP address of your host.

`-p, --port PORT`: The port number for the shell.

`-s, --shells`: List available reverse shell types.

`-b, --base64`: Base64 encode the reverse shell.

`-u, --urlencode`: URL encode the reverse shell.

`-l, --listener`: Start a listener.

## Available Shell Types:

- bash
- zsh
- nc-mkfifo
- nc
- php
- telnet
- python
- war
- powershell
- perl
- ruby

## Acknowledgements:

This tool was inspired by various reverse shell cheat sheets and is provided as-is with no warranties.

## License:

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://github.com/dw0rsec/revshellgen/blob/main/LICENSE) file for details.
