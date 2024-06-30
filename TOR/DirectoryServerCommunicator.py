# Global imports
import socket

# Project imports
from Constants import Constants
from Encryptions.DH import dh
from Encryptions.AES import aes
from Encryptions.RSA import public_key


# Classes
class DirectoryServerCommunicator:
    def __init__(self, server_port: int = 9000, server_address: str = Constants.IP):
        self.__address = server_address
        self.__port = server_port
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__connected = False
        self.__aes = None

    # Socket methods
    def __connect(self):
        if not self.__connected:
            self.__socket.connect((self.__address, self.__port))
            self.__connected = True
            self.__start()

    def __disconnect(self):
        if self.__connected:
            stop_request = self.__aes.encrypt("stop")
            self.__socket.sendall(stop_request.encode())
            self.__address = self.__port = self.__aes = None
            self.__connected = False

    def __start(self):
        self.__socket.sendall("start".encode())

        response = self.__socket.recv(Constants.BUFF_SIZE).decode().split(',')

        p, g = tuple(map(int, response[:2]))
        parameters = p, g

        server_public_key = int(response[2])

        DH = dh(parameters)

        private_number = dh.generate_private_number()
        dh_public_key = DH.generate_public_key(private_number)

        dh_key = DH.exchange(server_public_key, private_number)
        dh_key_hash = Constants.key_hash(dh_key)

        self.__socket.sendall(f"{dh_public_key},{dh_key_hash}".encode())
  
        response = self.__socket.recv(Constants.BUFF_SIZE).decode()

        if response != "started":
            raise ValueError

        self.__aes = aes(dh_key)

    def __send_and_receive(self, request: str):
        encrypted_request = self.__aes.encrypt(request)
        self.__socket.sendall(encrypted_request.encode())

        response = self.__socket.recv(Constants.BUFF_SIZE).decode()
        decrypted_response = self.__aes.decrypt(response)

        return decrypted_response

    def __send(self, request: str):
        encrypted_request = self.__aes.encrypt(request)
        self.__socket.sendall(encrypted_request.encode())

    def append(self, username: str, password: str, rsa_public_key: public_key, ip: str, port: int, allow_be_exit_node: bool = True, connect: bool = True, disconnect: bool = True) -> bool:
        if connect:
            self.__connect()

        append_request = f"append#{username},{password},{rsa_public_key.get_e()},{rsa_public_key.get_n()},{ip},{port},{int(allow_be_exit_node)}"
        append_response = self.__send_and_receive(append_request)

        if disconnect:
            self.__disconnect()
        return append_response == 'appended'

    def get_dh(self, connect: bool = True, disconnect: bool = True) -> tuple:
        if connect:
            self.__connect()

        get_dh_request = "get_dh"
        get_dh_response = self.__send_and_receive(get_dh_request)

        if disconnect:
            self.__disconnect()

        return tuple(map(int, get_dh_response.split(',')))

    def get_public_key(self, ip: str, port: int, connect: bool = True, disconnect: bool = True) -> public_key:
        if connect:
            self.__connect()

        get_public_key_request = f"get_rsa#{ip}:{port}"
        get_public_key_response = self.__send_and_receive(get_public_key_request)

        if disconnect:
            self.__disconnect()

        e, n = map(int, get_public_key_response.split(','))
        return public_key(e, n)

    def get_circuit(self, source_username: str, destination_username: str, connect: bool = True, disconnect: bool = True) -> tuple[int, list[str]]:
        if connect:
            self.__connect()

        construct_request = f"construct#{source_username},{destination_username}"
        construct_response = self.__send_and_receive(construct_request)

        response = construct_response.split(',')
        circuit_id = int(response[0])

        if disconnect:
            self.__disconnect()

        return circuit_id, response[1:]         # circuitId, user1, user2, ..., userN

    def send_teardown(self, not_available_ip: str, port: int, circ_id: int, connect: bool = True, disconnect: bool = False) -> None:
        if connect:
            self.__connect()

        construct_request = f"teardown#{not_available_ip},{port},{circ_id}"
        self.__send(construct_request)

        if disconnect:
            self.__disconnect()
