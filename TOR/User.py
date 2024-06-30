# Global imports
from queue import SimpleQueue

# Project Imports
from Client import Client
from Server import Server

from Encryptions.AES import aes
from Encryptions.RSA import rsa

from Constants import Constants
from Commands.Commands import Teardown
from DirectoryServerCommunicator import DirectoryServerCommunicator


# Classes
class User:
    """
    Class represents every program real user. It contains server and client part.
    """

    def __init__(self, server_port: int, username: str, password: str):
        """
        Constructor that runs server and creates client
        :param server_port: Port of server to be opened of current user
        :param username: user's entered username
        :param password: user's entered password
        """
        self.__username: str = username
        self.__password: str = Constants.str_hash(password)         # Hash password
        self.__server_port = server_port

        # Init rsa keys
        self.__rsa = rsa()

        # Add user to db request
        self.__directory_server = DirectoryServerCommunicator()
        append_result = self.__directory_server.append(username=self.__username,
                                                       password=self.__password,
                                                       rsa_public_key=self.__rsa.get_public_key(),
                                                       ip=Constants.IP,
                                                       port=self.__server_port,
                                                       allow_be_exit_node=True)

        if not append_result:
            raise Exception('Error adding user to database')

        # Run user's server part
        self.__server: Server = Server(server_port, self.__rsa.get_private_key())
        self.__server.run()

        # Create user's client part
        self.__client: Client = None

        # User's data
        self.__circuits: dict[int, list[str]] = {}              # { circuit_id: [address1, address2, address3, ...] }
        self.__connected_users: dict[int, str] = {}             # { circuit_id: username }
        self.__session_keys: dict[str, dict[int, aes]] = {}     # { address: { circuit_id: aes } }
        self.__streams: dict[str, int] = {}                     # { address: stream_id }

    def __insert_session_key(self, user_ip: str, circuit_id: int, aes_key: aes) -> None:
        """
        Method inserts to the list of session keys the current session key (by user ip and circuit id)
        :param user_ip: ip of the user that uses session key
        :param circuit_id: circuit id where session key used
        :param aes_key: add session key of specific user to our list of session keys
        """
        user_keys = self.__session_keys.setdefault(user_ip, {})
        user_keys[circuit_id] = aes_key

    def __get_session_key(self, user_address: str, circuit_id: int) -> aes | None:
        """
        Method gives the session keys (by user ip and circuit id)
        :param user_address: ip and port of the user that uses session key
        :param circuit_id: circuit id where session key used
        :return: None - in case where there is no session key | AES-key - in case if exist
        """
        user_keys = self.__session_keys.get(user_address)
        return None if (not user_keys) else user_keys.get(circuit_id)

    def __make_session_keys_queue(self, users_addresses: list[str], circuit_id: int) -> SimpleQueue[aes]:
        """
        Method makes queue of the session keys (to encrypt and decrypt by chain)
        :param users_addresses: list of users addresses (ip and port)
        :param circuit_id: current circuit id
        :return: Queue of the session keys to yse
        """
        aes_queue = SimpleQueue()

        for address in reversed(users_addresses):
            aes_key = self.__get_session_key(address, circuit_id)

            if aes_key is not None:
                aes_queue.put(aes_key)

        return aes_queue

    def __is_already_constructed(self, destination_username: str) -> str | None:
        """
        Method checks if circuit to the destination username is already constructed
        :param destination_username: the username of the destination user
        :return: address of the destination_username in case of success | else - None
        """
        if destination_username not in self.__connected_users.values():
            return None

        users = self.__connected_users

        circuit_ids = list(users.keys())
        destination_username_index = list(users.values()).index(destination_username)
        circuit_id = circuit_ids[destination_username_index]

        # Get last address (ip and port) in this ips chain
        return self.__circuits[circuit_id][-1]

    def __check_teardown(self, response, circuit_id: int) -> bool:
        """
        Method checks if last response is a teardown response. If yes - delete current circuit
        :param response: gotten response
        :circuit_id: current circuit id
        :return: True - if response caused a teardown | else - False
        """
        if not isinstance(response, Teardown):
            return False
        self.send_teardown(response.get_ip(), response.get_port(), response.get_id())
        self.__clear_sessions(circuit_id)

    def construct_circuit(self, destination_username: str) -> str:
        """
        Function constructs TOR circuit using `n` random nodes
        :param destination_username: username of the destination user
        :return: address of the destination username in terms of string
        """
        destination_address = self.__is_already_constructed(destination_username)

        if destination_address is not None:
            return destination_address

        circuit_id, users = self.__get_circuit(destination_username)

        users_copy = [user for user in users]
        self.__circuits[circuit_id] = users_copy

        # STRUCTURE OF users: [ 1_node_address, 2_node_address, ..., destination_address ]

        # Save address of the last destination
        destination_address = users[-1]

        print(f"\n\nCircuit ID: {circuit_id}\n{' -> '.join(users)}", end='\n\n')

        # Remove the destination and the entry node
        users.remove(destination_address)

        # Connect user client to the first node
        ip_0, port_0 = Constants.ip_and_port(users[0])
        self.__client = Client(circuit_id=circuit_id, server_ip=ip_0, server_port=port_0)

        # address_0 is off - send request to the directory server
        if not self.__client.connect():
            self.send_teardown(ip_0, port_0, circuit_id)
            return self.construct_circuit(destination_username)

        # Create circuit command. Get SK of entry node
        dh_0 = self.__client.create()
        self.__insert_session_key(users[0], circuit_id, aes(dh_0))

        # Start from second node (not entry)
        for address in users[1:]:

            # Send extend request to extend the circuit
            response = self.__client.extend(address, self.__make_session_keys_queue(users, circuit_id))

            # If extend response caused a teardown
            if self.__check_teardown(response, circuit_id):
                return self.construct_circuit(destination_username)

            # SK of the middle nodes
            dh_node = response
            self.__insert_session_key(address, circuit_id, aes(dh_node))

        # Begin circuit and get SK exit node
        response = self.__client.begin(self.__client.get_circId(),
                                       destination_address,
                                       self.__make_session_keys_queue(users, circuit_id))

        # If begin response caused a teardown
        if self.__check_teardown(response, circuit_id):
            return self.construct_circuit(destination_username)

        stream, dh_destination = response

        self.__streams[destination_address] = stream
        self.__insert_session_key(destination_address, circuit_id, aes(dh_destination))

        # Mark current username as already connected
        self.__connected_users[circuit_id] = destination_username

        # Return address (ip and port) of the last user
        return destination_address

    def send_data(self, data: str, address: str) -> None:
        """
        Function sends data from current user to the destination user using Onion Routing
        :param data: Data to send to destination user
        :param address: address (ip and port) of the destination user
        """
        if self.__client is None:
            print("[User Error] Client is None")
            return

        if not isinstance(self.__client, Client):
            print("[User Error] Client error")
            return

        for users_chain in self.__circuits.values():
            if users_chain[-1] == address:
                circuit_id = self.__client.get_circId()
                print(circuit_id)

                aes_keys = self.__make_session_keys_queue(users_chain, circuit_id)
                result = self.__client.data(circuit_id, self.__streams[address], data, aes_keys)

                print("[DATA SENT]: Successfully" if result else "[DATA ERROR]: Error sending data")

    def __get_circuit(self, destination_username: str) -> tuple[int, list[str]]:
        """
        Function connects to the DirectoryServer and asks for the `n` nodes for TOR circuit \n
        :param destination_username: Username of the destination user we want to construct circuit to
        :return: tuple of the circuit id and a list of nodes addresses by this structure: IP:PORT
        """
        self.__directory_server = DirectoryServerCommunicator()
        circuit_id, users = self.__directory_server.get_circuit(self.__username, destination_username)

        return circuit_id, users

    def send_teardown(self, not_available_ip: str, not_available_port: int, circuit_id: int) -> None:
        """
        Method sends teardown request to the directory server
        :param not_available_ip: ip of the not available user
        :param not_available_port: port of the not available user
        :param circuit_id: current circuit id
        """
        self.__directory_server = DirectoryServerCommunicator()
        self.__directory_server.send_teardown(not_available_ip, not_available_port, circuit_id)

    def __clear_sessions(self, circuit_id: int) -> None:
        """
        Method clears current session by circuit id
        :param circuit_id: current circuit id
        """
        users = self.__circuits[circuit_id]

        for user in users:
            if user in self.__session_keys.keys():
                self.__session_keys.pop(user)

        self.__circuits.pop(circuit_id)

    def end_connection(self) -> None:
        """
        Method ends client connection. And clears data
        """
        circuit_id = self.__client.get_circId()
        circuit = self.__circuits[circuit_id]
        stream_id = self.__streams[circuit[-1]]
        aes_list = [self.__get_session_key(user, circuit_id) for user in reversed(circuit)]

        self.__client.end(circuit_id, stream_id, aes_list)

    def destroy(self) -> None:
        """
        Methods sends to the directory server teardown request
        """
        self.__directory_server = DirectoryServerCommunicator()
        self.__directory_server.send_teardown(Constants.IP, self.__server_port, self.__client.get_circId())

    def check_for_received_data(self) -> tuple[int, int, str] | None:
        return self.__server.check_for_messages()

    def get_username(self) -> str:
        return self.__username
