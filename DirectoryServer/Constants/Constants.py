# Imports
import socket
from hashlib import sha256


# Server constant variables
IP = socket.gethostbyname(socket.gethostname())
PORT = 9000
BUFF_SIZE = 8192


# Codes
ERROR_CODE = -1


# Functions
def key_hash(key: int) -> str:
    """
    Function returns sha256 hash of the dh Key
    :param key: DH key to check his hash
    :return: The hash of the DH key
    """
    return sha256(str(key).encode()).hexdigest()


def print_message(client: bool, send: bool, sock: socket.socket, data: str) -> None:
    """
    Function prints message
    :param client: True - Client, False - Server
    :param send: True - Send/TO, else Receive/FROM
    :param sock: current socket
    :param data: data that sends/receives
    """
    peer = sock.getpeername()
    print(f"[{'Client' if client else 'Server'} Part {'Send' if send else 'Receive'}]")
    print(f"[{'TO' if send else 'FROM'}: {peer[0]}:{peer[1]}]")
    print(f"[Socket FD: {sock.fileno()}]\n-----------------------")
    print(f"Content: {repr(data)}")
    print("-----------------------\n\n\n")


def ip_and_port(ip_port: str) -> tuple[str, int]:
    """
    Function converts string of struct {ip:port} to ip and port
    :param ip_port: ip and port separated with ':'
    :return: A tuple that contains ip as string and port as int
    """
    ip, port = ip_port.split(':')
    return ip, int(port)
