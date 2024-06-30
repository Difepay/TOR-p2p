# Global Imports
import time
from queue import SimpleQueue

# Project imports
from Constants import Constants
from Commands import Commands

from ClientCommunicator import ClientCommunicator
from Encryptions.AES import aes


# Classes
class Client:
    def __init__(self, circuit_id: int, server_port: int, server_ip: str = Constants.IP):
        """
        Constructor of the Client class
        :param circuit_id: circuit_id
        :param server_port: Server port to make connection
        :param server_ip: Server ip to make connection
        """
        self.__communicator = ClientCommunicator(circuit_id, server_port, server_ip)
        self.__connected = False

    # Socket methods
    def connect(self) -> bool:
        """
        Function that connects client to the server. If it's not possible - change connected flag to false
        """
        try:
            self.__connected = self.__communicator.connect()
            print("--Connected to server--" if self.__connected else "--Error connecting--", end='\n\n\n')

        except Exception as e:
            print(f"[Client Error] connecting to server: {e}", end='\n\n\n')

        return self.__connected

    def disconnect(self) -> None:
        """
        Function that disconnects client from the server
        """
        if not self.__connected:
            raise Exception("Not connected to server")

        if self.__connected:
            self.__communicator.disconnect()
            self.__connected = False
            print("--Disconnected from server--", end='\n\n\n')

    def send_request(self, data: str) -> None:
        """
        Function that sends request to the server
        :param data: Data to send to the server
        """
        if not self.__connected:
            raise Exception("Not connected to server")

        try:
            self.__communicator.send_request(data)

        except Exception as e:
            print(f"[Client Error] sending request: {e}", end='\n\n\n')

    def receive_response(self, timeout: int = 5) -> str:
        """
        Function that receives and returns a data from the server
        :param timeout: Timeout of the message in seconds
        :return: Decoded data from the server
        """
        if not self.__connected:
            raise Exception("Not connected to server")

        start_time = time.time()

        data = self.__communicator.receive_response()

        if data:
            return data

        if time.time() - start_time > timeout:
            raise TimeoutError("Response timeout exceeded")

    def send_and_receive(self, data: str) -> str:
        """
        Function sends data to server and then returns the response
        :param data: Data to send to the server
        :return: Decoded response from the server
        """
        self.send_request(data)
        return self.receive_response()

    # TOR methods
    def create(self) -> int:
        """
        Function do `create` command TOR logic
        :return: Session key of the next node
        """
        return self.__communicator.create()

    def extend(self, ip_and_port: str, aes_keys: SimpleQueue[aes]) -> int | Commands.Teardown:
        """
        Function do `extend` command TOR logic
        :param ip_and_port: ip and port of the next node of the next node
        :param aes_keys: queue of aes keys to encrypt and decrypt the message
        :return: Session key of the next node of the next node
        """
        return self.__communicator.extend(ip_and_port, aes_keys)

    def begin(self, circId: int, ip_and_port: str, aes_keys: SimpleQueue[aes]) -> tuple[int, int] | Commands.Teardown:
        """
        Function do `begin` command TOR logic
        :param circId: current circuit ID
        :param ip_and_port: ip and port of the destination user
        :param aes_keys: queue of aes keys to encrypt and decrypt the message
        :return: Stream id of the current conversation
        """
        return self.__communicator.begin(circId, ip_and_port, aes_keys)

    def end(self, circId: int, stream_id: int, aes_keys: SimpleQueue[aes]) -> None:
        return self.__communicator.end(circId, stream_id, aes_keys)

    def data(self, circId: int, stream_id: int, data: str, aes_keys: SimpleQueue[aes]) -> bool:
        """
        Function sends data to the destination user using TOR
        :param circId: Current circuit ID
        :param stream_id: ID of the stream to send data
        :param data: Data to send
        :param aes_keys: queue of aes keys to encrypt and decrypt the message
        :return: The response of the destination user
        """
        return self.__communicator.data(circId, stream_id, data, aes_keys)

    def get_circId(self) -> int:
        """
        Function returns current circuit ID
        :return: current circuit ID
        """
        return self.__communicator.get_circId()
