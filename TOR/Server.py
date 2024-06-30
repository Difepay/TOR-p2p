# Imports
import threading

from ServerCommunicator import ServerCommunicator
from Encryptions.RSA import private_key


# Classes
class Server:
    """
    Server wrapper class of Server communicator
    """

    def __init__(self, port: int, rsa_private_key: private_key):
        """
        Constructor of the Server class
        :param port: Port that server must be opened on
        :param rsa_private_key: RSA private key that user generated
        """
        self.__communicator = ServerCommunicator(port, rsa_private_key)

    def run(self) -> None:
        """
        Function binds, listens and runs server in the other detached thread
        """
        self.__communicator.bind_and_listen()

        # Start new thread and detach it
        server_thread = threading.Thread(target=self.__communicator.start_handle_requests)
        server_thread.daemon = True
        server_thread.start()

    def check_for_messages(self) -> tuple[int, int, str] | None:
        return self.__communicator.check_for_messages()
