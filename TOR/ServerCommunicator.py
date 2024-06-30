# Imports
import socket
import threading

from Commands import Commands
from Constants import Constants
from Client import Client

from Encryptions.DH import dh
from Encryptions.AES import aes
from Encryptions.RSA import rsa, private_key


# Classes
class ServerCommunicator:

    # Constructor
    def __init__(self, port: int, rsa_private_key: private_key):
        """
        Constructor for the server communicator
        :param port: Port to open server
        """
        self.__server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__port: int = port
        self.__rsa_private_key: private_key = rsa_private_key

        self.__mutex = threading.Lock()
        self.__next_mutex = threading.Lock()
        self.__streams_mutex = threading.Lock()
        self.__prev_mutex = threading.Lock()

        self.__session_keys = {}
        self.__clients = {}
        self.__streams: dict[list[Client]] = {}
        self.__nexts = {}
        self.__prev = {}

        self.__messages: dict[int, dict[int, list[str]]] = {}       # { circuit_id_1: { stream_id_1: [ message_1, message_2, ... ], stream_id_2: [ message_1, ... ], }  }

    # Socket methods
    def bind_and_listen(self) -> None:
        """
        Function binds server and listens given port
        """
        address = (socket.gethostbyname(socket.gethostname()), self.__port)
        self.__server.bind(address)
        self.__server.listen()

    def start_handle_requests(self) -> None:
        """
        Function handle new clients that wants to connect to the server (handle them in the detached thread)
        """
        while True:
            client_socket, address = self.__server.accept()
            print(f"[SERVER PART - NEW]: Client connected from {address[0]}:{address[1]}", end='\n\n\n')

            with self.__mutex:
                self.__clients[client_socket] = address

            client_thread = threading.Thread(target=self.__handle_new_client,
                                             args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()

    @staticmethod
    def __receive_request(client_socket: socket.socket) -> str | None:
        """
        Function receives data from the client socket
        :param client_socket: socket of the client to receive data
        :return: None if error occurs | else - tuple by this struct: time, command, data
        """
        try:
            request_info = client_socket.recv(Constants.BUFF_SIZE).decode()
            Constants.print_message(False, False, client_socket, request_info)

            return request_info

        except socket.error:
            return None

    @staticmethod
    def __send_response(client_socket: socket.socket, response: str) -> bool:
        """
        Function sends request to the client
        :param client_socket: socket of the client to send data
        :param response: response to send to the client
        :return: False if error occurs | else - True
        """
        try:
            client_socket.sendall(response.encode())
            Constants.print_message(False, True, client_socket, response)

            return True

        except socket.error:
            return False

    def __pass_command(self, curr_client: socket.socket, request: str) -> None:
        """
        Function passes the request to the next node if possible
        :param curr_client: current socket of the client
        :param request: request to pass
        """
        with self.__next_mutex:
            self.__nexts[curr_client].send_request(request)
            response = self.__nexts[curr_client].receive_response()
            response_encrypted = self.__session_keys[curr_client].encrypt(response)
            self.__send_response(curr_client, response_encrypted)

    def __handle_new_client(self, client_socket: socket.socket) -> None:
        """
        Function handles clients requests, and sends responses
        :param client_socket: current client socket to make conversation
        """
        while True:
            try:
                request = ServerCommunicator.__receive_request(client_socket)

                if request is None or len(request) == 0:
                    print("[SERVER] Client closed connection.")
                    break

                # If the session key that is established in the handle create has not been created yet
                if client_socket not in self.__session_keys.keys():
                    request_code = int(request.split('#')[0])

                    if request_code == Commands.Create.REQUEST_CODE:
                        self.__handle_create_request(client_socket, request)
                    continue

                request_decoded = self.__session_keys[client_socket].decrypt(request)
                Constants.print_message(False, False, client_socket, request_decoded)

                # If already has next just pass it to the next node
                if client_socket in self.__nexts.keys():
                    self.__pass_command(client_socket, request_decoded)
                    continue

                request_code = int(request_decoded[0])

                # Only if the session key has been created check for other commands
                if request_code == Commands.Extend.REQUEST_CODE:
                    self.__handle_extend_request(client_socket, request_decoded)

                elif request_code == Commands.Begin.REQUEST_CODE:
                    self.__handle_begin_request(client_socket, request_decoded)

                elif request_code == Commands.End.REQUEST_CODE:
                    self.__handle_end_request(client_socket, request_decoded)

                elif request_code == Commands.Data.REQUEST_CODE:
                    self.__handle_data_request(client_socket, request_decoded)

            except ...:
                break

        with self.__mutex:
            del self.__clients[client_socket]

    # TOR methods
    def __handle_create_request(self, client_socket: socket.socket, create_request: str) -> None:
        """
        Function handles TOR's create request. In other words make connection with the first node, and sends to the user
        TOR's created response
        :param client_socket: current client socket
        :param create_request: TOR's create request
        """
        # Convert request to an object
        create = Commands.Create(create_request)

        # DH logic
        parameters = create.get_dh_p(), create.get_dh_g()
        server_dh = dh(parameters)

        private_dh_number = dh.generate_private_number()
        public_dh_key = server_dh.generate_public_key(private_dh_number)

        # RSA logic
        rsa_dh_handshake = create.get_RSA_DH_handshake()
        rsa_dh_decrypted = rsa.decrypt(rsa_dh_handshake, self.__rsa_private_key)

        # Session key
        dh_key = server_dh.exchange(rsa_dh_decrypted, private_dh_number)

        # Send request
        request = Commands.Created.compose_response(create.get_id(), public_dh_key, Constants.key_hash(dh_key))

        with self.__prev_mutex:
            self.__prev[create.get_id()] = client_socket

        ServerCommunicator.__send_response(client_socket, request)

        # Add new session key
        self.__session_keys[client_socket] = aes(dh_key)

    def __handle_extend_request(self, client_socket: socket.socket, extend_request: str) -> None:
        """
        Function handles TOR's extent request. In other words make connection with the second node, and sends to the
        user TOR's extended response
        :param client_socket: current client socket
        :param extend_request: TOR's extend request
        """
        # Convert request to an object
        extend = Commands.Extend(extend_request)

        # Connect new client to the next node
        ip, port = Constants.ip_and_port(extend.get_user_ip_and_port())

        client = Client(extend.get_id(), port, ip)

        if client.connect():
            with self.__next_mutex:
                if client_socket not in self.__nexts.keys():
                    self.__nexts[client_socket] = client

            # Send request and receive response
            create_request = Commands.Create.compose_request(extend.get_id(), extend.get_dh_p(), extend.get_dh_g(), extend.get_RSA_DH_handshake())
            created = client.send_and_receive(create_request)

            if created:
                created = Commands.Created(created)
                extended = Commands.Extended.compose_response(created.get_id(),
                                                              created.get_DH_handshake(),
                                                              created.get_key_hash())

                extended_encrypted = self.__session_keys[client_socket].encrypt(extended)
                ServerCommunicator.__send_response(client_socket, extended_encrypted)
        else:
            teardown = Commands.Teardown.compose_request(extend.get_id(), ip, port)
            teardown_encrypted = self.__session_keys[client_socket].encrypt(teardown)
            ServerCommunicator.__send_response(client_socket, teardown_encrypted)

            self.__teardown(client_socket)

    def __handle_begin_request(self, client_socket: socket.socket, begin_request: str) -> None:
        """
        Function handles TOR's begin request. In other words after construct of circuit if user has next - pass
        else connects to the destination. After it sends to the user TOR's connected request
        :param client_socket: current client socket
        :param begin_request: TOR's begin request
        """
        # Convert request to an object
        begin = Commands.Begin(begin_request)

        # Connect new client to the destination
        ip, port = Constants.ip_and_port(begin.get_user_ip_and_port())

        client = Client(begin.get_id(), port, ip)

        if client.connect():
            with self.__streams_mutex:
                if client_socket not in self.__nexts.keys():
                    self.__nexts[client_socket] = client

                self.__streams[client_socket] = [..., client]
                stream_id = len(self.__streams[client_socket]) - 1

                # Send create request to the destination and receive response
                create_request = Commands.Create.compose_request(begin.get_id(), begin.get_dh_p(), begin.get_dh_g(), begin.get_RSA_DH_handshake())
                created = client.send_and_receive(create_request)

                if not created:
                    teardown = Commands.Teardown.compose_request(begin.get_id(), ip, port)
                    teardown_encrypted = self.__session_keys[client_socket].encrypt(teardown)
                    ServerCommunicator.__send_response(client_socket, teardown_encrypted)

                    return self.__teardown(client_socket)

                created = Commands.Created(created)

                connected = Commands.Connected.compose_response(begin.get_id(), stream_id, created.get_DH_handshake(), created.get_key_hash())
                connected_encrypted = self.__session_keys[client_socket].encrypt(connected)
                ServerCommunicator.__send_response(client_socket, connected_encrypted)
        else:
            teardown = Commands.Teardown.compose_request(begin.get_id(), ip, port)
            teardown_encrypted = self.__session_keys[client_socket].encrypt(teardown)
            ServerCommunicator.__send_response(client_socket, teardown_encrypted)

            self.__teardown(client_socket)

    def __handle_end_request(self, client_socket: socket.socket, end_request: str) -> None:
        """
        Function disconnect users from the circuit
        :param client_socket: current client socket
        :param end_request: request to end the circuit conversation
        """
        end = Commands.End(end_request)

        with self.__streams_mutex:
            self.__streams[client_socket][end.get_stream_id()].disconnect()
            self.__streams[client_socket].pop(end.get_stream_id())

    def __teardown(self, client_socket: socket.socket) -> None:
        """
        Function deletes all circuit information such as clients, session keys, nodes
        :param client_socket: current client socket
        """
        with self.__next_mutex:
            self.__nexts.pop(client_socket, None)
            self.__clients.pop(client_socket, None)
            self.__session_keys.pop(client_socket, None)

    def __handle_data_request(self, client_socket: socket.socket, data_request: str) -> None:
        """
        Function handles data request, when get request with data's code
        :param client_socket: current client socket
        :param data_request: exact request that client sent
        """
        data = Commands.Data(data_request)
        data_message = data.get_data()

        circuit_id = data.get_id()
        stream_id = data.get_stream_id()

        # Ensure the dictionary is initialized properly
        if circuit_id not in self.__messages.keys():
            self.__messages[circuit_id] = {}

        if stream_id not in self.__messages[circuit_id].keys():
            self.__messages[circuit_id][stream_id] = []

        self.__messages[circuit_id][stream_id].append(data_message)

        print(f"User sent message: {data_message}", end='\n\n')

        confirm = Commands.Confirm.compose_response(data.get_id(), 1, data_message)
        confirm_encrypted = self.__session_keys[client_socket].encrypt(confirm)
        ServerCommunicator.__send_response(client_socket, confirm_encrypted)

    def check_for_messages(self) -> tuple[int, int, str] | None:
        if not self.__messages:
            return

        for circuit_id, dict_of_messages in self.__messages.items():
            for stream_id, list_of_messages in dict_of_messages.items():
                if list_of_messages:
                    return circuit_id, stream_id, list_of_messages.pop(0)
        return None
