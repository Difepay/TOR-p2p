# Global imports
import socket
import threading

import os
import sys


# Function
def add_directory_server_paths():
    project_base_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(os.path.join(project_base_path, 'DataBaseManager'))
    sys.path.append(os.path.join(project_base_path, 'Encryptions'))
    sys.path.append(os.path.join(project_base_path, 'Constants'))


add_directory_server_paths()

# Project imports
from Encryptions.DH import dh
from Encryptions.AES import aes
from Encryptions.RSA import rsa

from DataBaseManager.DataBase import DataBase
from DataBaseManager.DataBaseUser import DataBaseUser

from Constants import Constants


# Classes
class ExternalServer:
    """
    Class of external server that must be running, to provide to TOR nodes required data
    """

    # Path to the DB file. Can be changed
    DB_PATH = '../DataBase/TOR_DB.db'

    def __init__(self, db_path: str = None):
        """
        Constructor of the external server that initialize fields
        :param db_path: path to the database file (to create)
        """
        dp_path = ExternalServer.DB_PATH if (db_path is None) else db_path
        self.__db = DataBase(dp_path)

        self.__server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__mutex = threading.Lock()

        self.__aes_keys: dict[socket.socket, aes] = {}
        self.__circuit_ids: dict[int, list[tuple]] = {}

    def start_server(self) -> None:
        """
        Method starts the server, listening for the new clients, and run detached thread for everyone
        """
        try:
            self.__server_socket.bind((Constants.IP, Constants.PORT))
            self.__server_socket.listen()

            print(f"[Directory Server] Bind ON {Constants.IP}:{Constants.PORT}", end='\n\n\n')
            print(f"[Directory Server] Start listen port: {Constants.PORT}", end='\n\n\n')

            while True:
                client_socket, client_address = self.__server_socket.accept()

                client_thread = threading.Thread(target=self.__handle_new_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()

        except OSError as e:
            print(e)
            exit(1)

    def __handle_new_client(self, client_socket: socket.socket) -> None:
        """
        Method to handle new clients (runs in detached thread for each new connected client).
        Method runs infinity until user is disconnected
        :param client_socket: the socket with the current client
        """

        # Aes of the client (currently none)
        AES = None

        while True:
            request = client_socket.recv(Constants.BUFF_SIZE).decode()

            if not request:
                continue

            if (request == "start") and not AES:
                with self.__mutex:
                    Constants.print_message(False, False, client_socket, request)

                current_dh_key = ExternalServer.__handle_start_request(client_socket)

                if current_dh_key != Constants.ERROR_CODE:
                    AES = aes(current_dh_key)
                    with self.__mutex:
                        self.__aes_keys[client_socket] = AES

                continue

            # Decrypt the request (if encrypted)
            decrypted_request = AES.decrypt(request)

            with self.__mutex:
                Constants.print_message(False, False, client_socket, decrypted_request)

            if decrypted_request == "get_dh":
                ExternalServer.__handle_dh_request(client_socket, AES)

            elif decrypted_request.startswith("get_rsa"):
                self.__handle_rsa_request(client_socket, decrypted_request, AES)

            elif decrypted_request.startswith("append"):
                self.__handle_append_request(client_socket, decrypted_request, AES)

            elif decrypted_request.startswith("construct"):
                self.__handle_construct_request(client_socket, decrypted_request, AES)

            elif decrypted_request.startswith("teardown"):
                self.__handle_teardown_request(decrypted_request)

            elif decrypted_request.startswith("stop"):
                break

            else:
                break

        client_socket.close()

    @staticmethod
    def __handle_start_request(client_socket: socket.socket) -> int:
        """
        Static method that handles start request for each user
        :param client_socket: socket of the current user
        :return: the final dh key between client and directory server
        """
        client_parameters = p, g = dh.generate_parameters()

        DH = dh(client_parameters)
        private_number = dh.generate_private_number()
        public_key = DH.generate_public_key(private_number)

        dh_response = f"{p},{g},{public_key}"

        client_socket.sendall(dh_response.encode())
        Constants.print_message(False, True, client_socket, dh_response)

        dh_request = client_socket.recv(Constants.BUFF_SIZE).decode()
        Constants.print_message(False, False, client_socket, dh_request)

        public_key, dh_hash = dh_request.split(',')
        dh_key = DH.exchange(int(public_key), private_number)

        if Constants.key_hash(dh_key) != dh_hash:
            return Constants.ERROR_CODE

        client_socket.sendall("started".encode())
        Constants.print_message(False, True, client_socket, "started")

        return dh_key

    @staticmethod
    def __handle_dh_request(client_socket: socket.socket, AES: aes) -> None:
        """
        Static method that handles dh request for each user.
        Just to get random p, g dh parameters from the server \n
        :param client_socket: socket of the current user
        :param AES: aes instance of the current user - to encrypt message
        """
        p, g = dh.generate_parameters()

        get_dh_response = f"{p},{g}"
        get_dh_response_encrypted = AES.encrypt(get_dh_response)

        client_socket.sendall(get_dh_response_encrypted.encode())
        Constants.print_message(False, True, client_socket, get_dh_response_encrypted)

    def __handle_rsa_request(self, client_socket: socket.socket, request: str, AES: aes) -> None:
        """
        Static method that handles rsa request for each user.
        Sends to the user rsa public key by given ip and port \n
        :param client_socket: socket of the current user
        :param request: the request string
        :param AES: aes instance of the current user - to encrypt message
        """
        ip, port = Constants.ip_and_port(request.split('#')[1])

        with self.__mutex:
            rsa_public_key = self.__db.get_rsa_by_ip(ip, port)

        get_public_key_response = f"{rsa.PUBLIC_EXPONENT},{rsa_public_key}"
        get_public_key_response_encrypted = AES.encrypt(get_public_key_response)

        client_socket.sendall(get_public_key_response_encrypted.encode())

        with self.__mutex:
            Constants.print_message(False, True, client_socket, get_public_key_response_encrypted)

    def __handle_append_request(self, client_socket: socket.socket, request: str, AES: aes) -> None:
        """
        Static method that handles append request for each user.
        Adds user to the database \n
        :param client_socket: socket of the current user
        :param request: the request string
        :param AES: aes instance of the current user - to encrypt message
        """
        parameters = request.split('#')[1]

        user = DataBaseUser(parameters)
        result = False

        with self.__mutex:
            if not self.__db.does_username_exists(user.get_username()):
                result = self.__db.add_user(user)

            elif self.__db.is_password_valid(user.get_username(), user.get_password()):
                result = self.__db.change_ip_and_port(user.get_username(), user.get_port(), user.get_ip()) and \
                         self.__db.change_rsa_public_key(user) and \
                         self.__db.change_availability(user.get_ip(), user.get_port(), available=1)

        append_response = "appended" if result else "error"
        append_response_encrypted = AES.encrypt(append_response)

        client_socket.sendall(append_response_encrypted.encode())
        with self.__mutex:
            Constants.print_message(False, True, client_socket, append_response_encrypted)

    def __handle_construct_request(self, client_socket: socket.socket, request: str, AES: aes) -> None:
        """
        Static method that handles construct request for each user.
        Chose random three users from database and sends their ip and ports
        :param client_socket: socket of the current user
        :param request: the request string
        :param AES: aes instance of the current user - to encrypt message
        """
        source, destination = request.split('#')[1].split(',', 1)

        if source == destination:
            message = AES.encrypt('error')
            client_socket.sendall(message.encode())

        with self.__mutex:
            users = self.__db.get_circuit(source, destination)
            circuit_id = self.__generate_circuit_id()

            self.__circuit_ids[circuit_id] = users

        # ip:port of each user
        users = [f"{user[DataBase.IP_INDEX]}:{user[DataBase.PORT_INDEX]}" for user in users]

        response = f"{circuit_id},{','.join(users)}"
        response_encrypted = AES.encrypt(response)

        client_socket.sendall(response_encrypted.encode())
        with self.__mutex:
            Constants.print_message(False, True, client_socket, response_encrypted)

    def __handle_teardown_request(self, request: str) -> None:
        """
        Static method that handles teardown request for each user.
        Deletes circuit id from the list and changes user's availability
        :param request: the request string
        """
        not_available_ip, port, circuit_id = request.split('#')[1].split(',', 2)

        with self.__mutex:
            self.__circuit_ids.pop(circuit_id, None)
            self.__db.change_availability(not_available_ip, port)

    def __generate_circuit_id(self) -> int:
        """
        Function generates circuit id (unique)
        :return: the new generated circuit id
        """
        ids = set(self.__circuit_ids.keys())

        new_id = 1
        while new_id in ids:
            new_id += 1

        return new_id


# Main function
def main():
    """
    Main function that runs the external server
    """
    server = ExternalServer()
    server.start_server()


# Program start
if __name__ == "__main__":
    main()
