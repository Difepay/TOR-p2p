# Global imports
import socket
from queue import SimpleQueue

# Project imports
from Commands import Commands
from Constants import Constants
from DirectoryServerCommunicator import DirectoryServerCommunicator

from Encryptions.DH import dh
from Encryptions.AES import aes
from Encryptions.RSA import rsa


# Classes
class ClientCommunicator:

    def __init__(self, circId: int, server_port: int, server_address: str):
        """
        Constructor of the ClientCommunicator class
        :param server_port: server port to connect to
        :param server_address: server ip to connect to
        """
        self.__address = server_address
        self.__port = server_port
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__connected = False
        self.__circId = circId

    # Socket methods
    def connect(self) -> bool:
        """
        Function connects client to the server, if it's possible
        :return: True - if succeeded | False - otherwise
        """
        try:
            self.__socket.connect((self.__address, self.__port))
            self.__connected = True

        except ...:
            self.__connected = False

        finally:
            return self.__connected

    def send_request(self, data: str) -> bool:
        """
        Sends a request to the server
        :param data: The request data to be sent
        :return: True if the request was sent successfully, False otherwise
        """
        if not self.__connected:
            return False

        try:
            self.__socket.sendall(data.encode())
            Constants.print_message(True, True, self.__socket, data)
            return True

        except ...:
            return False

    def receive_response(self) -> str:
        """
        Receives a response from the server
        :return: The received response data as bytes or None if an error occurred
        """
        if not self.__connected:
            return ''

        try:
            data = self.__socket.recv(Constants.BUFF_SIZE).decode()
            Constants.print_message(True, False, self.__socket, data)

            return data

        except ...:
            return ''

    def disconnect(self) -> None:
        """
        Disconnects from the server
        """
        if self.__connected and self.__socket:
            self.__socket.close()
            self.__connected = False

    # TOR methods
    def create(self) -> int:
        """
        Function sends TOR's create request, gets `created` response and returns session key with first node
        :return: session key with the first node
        """
        # Get parameters from the server
        directory = DirectoryServerCommunicator()
        parameters = directory.get_dh(disconnect=False)

        # DH logic
        client_dh = dh(parameters)
        private_dh_number = dh.generate_private_number()
        public_dh_key = client_dh.generate_public_key(private_dh_number)

        # RSA logic
        public_rsa_key = directory.get_public_key(self.__address, self.__port, connect=False)
        rsa_dh_handshake = rsa.encrypt(public_dh_key, public_rsa_key)

        # Send request
        create_request = Commands.Create.compose_request(self.__circId, parameters[0], parameters[1], rsa_dh_handshake)
        self.send_request(create_request)

        # Receive response
        created_response = self.receive_response()
        created = Commands.Created(created_response)

        # Session key logic
        dh_key = client_dh.exchange(created.get_DH_handshake(), private_dh_number)

        assert created.get_key_hash() == Constants.key_hash(dh_key), "Hash and key hash aren't same"
        return dh_key

    def extend(self, ip_and_port: str, aes_keys_queue: SimpleQueue[aes]) -> int | Commands.Teardown:
        """
        Function sends TOR's extend request, gets `extended` response and returns session key with seconds node
        :param ip_and_port: ip and port of the second node
        :param aes_keys_queue: queue of aes keys to encrypt and decrypt the message
        :return: session key with the second node
        """
        # Get dh from the server
        directory = DirectoryServerCommunicator()
        parameters = directory.get_dh(disconnect=False)

        # DH logic
        client_dh = dh(parameters)
        private_dh_number = dh.generate_private_number()
        public_dh_key = client_dh.generate_public_key(private_dh_number)

        # RSA logic
        last_node_ip, last_node_port = Constants.ip_and_port(ip_and_port)
        public_rsa_key = directory.get_public_key(last_node_ip, last_node_port, connect=False)
        rsa_dh_handshake = rsa.encrypt(public_dh_key, public_rsa_key)

        # Send request
        extend_request = Commands.Extend.compose_request(self.__circId, ip_and_port, parameters[0], parameters[1], rsa_dh_handshake)
        extend_request, aes_keys_stack = Constants.encrypt_by_aes_chain(extend_request, aes_keys_queue)
        self.send_request(extend_request)

        # Receive response
        response = self.receive_response()
        response = Constants.decrypt_by_aes_chain(response, aes_keys_stack)

        # Define the type
        command = Commands.get_command(response)

        # If got teardown instead of extended
        if command == Commands.Teardown.REQUEST_CODE:
            return Commands.Teardown(response)

        # If got correct extended
        extended = Commands.Extended(response)

        # Session key logic
        dh_key = client_dh.exchange(extended.get_DH_handshake(), private_dh_number)

        assert extended.get_key_hash() == Constants.key_hash(dh_key), "Hash and key hash aren't same"
        return dh_key

    def begin(self, circId: int, ip_and_port: str, aes_keys_queue: SimpleQueue[aes]) -> tuple[int, int] | Commands.Teardown:
        """
        Function sends TOR's begin request, gets `connected` response and returns its stream ID
        :param circId: current circuit ID
        :param ip_and_port: ip and port of destination user
        :param aes_keys_queue queue of aes keys to encrypt and decrypt the message
        :return: stream id of the conversation
        """
        # Get dh from the server
        directory = DirectoryServerCommunicator()
        parameters = directory.get_dh(disconnect=False)

        # DH logic
        client_dh = dh(parameters)
        private_dh_number = dh.generate_private_number()
        public_dh_key = client_dh.generate_public_key(private_dh_number)

        # RSA logic
        destination_ip, destination_port = Constants.ip_and_port(ip_and_port)
        public_rsa_key = directory.get_public_key(destination_ip, destination_port, connect=False)
        rsa_dh_handshake = rsa.encrypt(public_dh_key, public_rsa_key)

        # Send request
        begin_request = Commands.Begin.compose_request(circId, ip_and_port, parameters[0], parameters[1], rsa_dh_handshake)
        begin_request, aes_keys_stack = Constants.encrypt_by_aes_chain(begin_request, aes_keys_queue)
        self.send_request(begin_request)

        # Receive response
        response = self.receive_response()
        response = Constants.decrypt_by_aes_chain(response, aes_keys_stack)

        # Define the type
        command = Commands.get_command(response)

        # If got teardown instead of connected
        if command == Commands.Teardown.REQUEST_CODE:
            return Commands.Teardown(response)

        # If got correct connected
        connected = Commands.Connected(response)

        # Session key logic
        dh_key = client_dh.exchange(connected.get_DH_handshake(), private_dh_number)

        assert connected.get_key_hash() == Constants.key_hash(dh_key), "Hash and key hash aren't same"
        return connected.get_stream_id(), dh_key

    def end(self, circId: int, stream_id: int, aes_keys_queue: SimpleQueue[aes]) -> None:
        """
        Function sends TOR's end request
        :param circId: circuit id
        :param stream_id: id of the stream
        :param aes_keys_queue queue of aes keys to encrypt and decrypt the message
        """
        end_request = Commands.End.compose_request(circId, stream_id)
        end_request, _ = Constants.encrypt_by_aes_chain(end_request, aes_keys_queue)
        self.send_request(end_request)

    def data(self, circId: int, stream_id: int, data: str, aes_keys_queue: SimpleQueue[aes]) -> bool:
        """
        Function sends data to the destination user
        :param circId: current circuit ID
        :param stream_id: current stream ID to send data
        :param data: data to send
        :param aes_keys_queue queue of aes keys to encrypt and decrypt the message
        :return: Answer of the destination user
        """

        # Send data request
        data_request = Commands.Data.compose_request(circId, stream_id, data)
        data_request, aes_keys_stack = Constants.encrypt_by_aes_chain(data_request, aes_keys_queue)
        self.send_request(data_request)

        # Receive data response (confirm)
        response = self.receive_response()
        response = Constants.decrypt_by_aes_chain(response, aes_keys_stack)

        # Check if data was successfully sent
        if Commands.get_command(response) == Commands.Confirm.REQUEST_CODE:
            confirm = Commands.Confirm(response)
            return (confirm.get_status() == 1) and (confirm.get_data() == data)
        return False

    def get_circId(self) -> int:
        """
        Function returns current circuit ID
        :return: current circuit ID
        """
        return self.__circId
