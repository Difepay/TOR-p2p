import socket
from hashlib import sha256

from queue import SimpleQueue, LifoQueue


# Constant variables
IP = socket.gethostbyname(socket.gethostname())
BUFF_SIZE = 8192


# Functions
def key_hash(key: int) -> str:
    """
    Function returns sha256 hash of the dh Key
    :param key: DH key to return his hash
    :return: The hash of the DH key
    """
    return sha256(str(key).encode()).hexdigest()


def str_hash(string: str) -> str:
    """
    Function returns sha256 hash of string
    :param string: string to get it hash
    :return: The hash of the given string
    """
    return sha256(string.encode()).hexdigest()


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


def encrypt_by_aes_chain(data: str, aes_queue: SimpleQueue) -> tuple[str, LifoQueue]:
    aes_stack = LifoQueue()

    while not aes_queue.empty():
        key = aes_queue.get()
        aes_stack.put(key)
        data = key.encrypt(data)

    return data, aes_stack


def decrypt_by_aes_chain(data: str, aes_stack: LifoQueue) -> str:
    while not aes_stack.empty():
        data = aes_stack.get().decrypt(data)

    return data
