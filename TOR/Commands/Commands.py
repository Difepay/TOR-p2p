# Classes
class Create:
    REQUEST_CODE = 1

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[1]
        commands = commands.split(',', 3)

        self.__circId = int(commands[0])
        self.__p = int(commands[1])
        self.__g = int(commands[2])
        self.__RSA_DH_handshake = int(commands[3])

    def get_id(self) -> int:
        return self.__circId

    def get_RSA_DH_handshake(self) -> int:
        return self.__RSA_DH_handshake

    def get_dh_p(self) -> int:
        return self.__p

    def get_dh_g(self) -> int:
        return self.__g

    @staticmethod
    def compose_request(circId: int, p: int, g: int, RSA_DH_handshake: int) -> str:
        return f'{Create.REQUEST_CODE}#{circId},{p},{g},{RSA_DH_handshake}'


class Created:
    REQUEST_CODE = 2

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 2)

        self.__circId = int(commands[0])
        self.__DH_handshake = int(commands[1])
        self.__key_hash = commands[2]

    def get_id(self) -> int:
        return self.__circId

    def get_DH_handshake(self) -> int:
        return self.__DH_handshake

    def get_key_hash(self) -> str:
        return self.__key_hash

    @staticmethod
    def compose_response(circId: int, DH_handshake: int, key_hash: str) -> str:
        return f'{Created.REQUEST_CODE}#{circId},{DH_handshake},{key_hash}'


class Destroy:
    REQUEST_CODE = 3

    def __init__(self, commands: list):
        self.__circId = int(commands[0])

    def get_id(self) -> int:
        return self.__circId


class Data:
    REQUEST_CODE = 4

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 2)

        self.__circId = int(commands[0])
        self.__streamId = int(commands[1])
        self.__data = commands[2]

    def get_id(self) -> int:
        return self.__circId

    def get_data(self) -> str:
        return self.__data

    def get_stream_id(self) -> int:
        return self.__streamId

    @staticmethod
    def compose_request(circId: int, stream_id: int, data: str) -> str:
        return f"{Data.REQUEST_CODE}#{circId},{stream_id},{data}"


class Begin:
    REQUEST_CODE = 5

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 4)

        self.__circId = int(commands[0])
        self.__user_ip_and_port = commands[1]
        self.__p = int(commands[2])
        self.__g = int(commands[3])
        self.__RSA_DH_handshake = int(commands[4])

    def get_id(self) -> int:
        return self.__circId

    def get_user_ip_and_port(self) -> str:
        return self.__user_ip_and_port

    def get_RSA_DH_handshake(self) -> int:
        return self.__RSA_DH_handshake

    def get_dh_p(self) -> int:
        return self.__p

    def get_dh_g(self) -> int:
        return self.__g

    @staticmethod
    def compose_request(circId: int, ip_and_port: str, p: int, g: int, RSA_DH_handshake: int) -> str:
        return f"{Begin.REQUEST_CODE}#{circId},{ip_and_port},{p},{g},{RSA_DH_handshake}"


class End:
    REQUEST_CODE = 6

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 1)

        self.__circId = int(commands[0])
        self.__streamId = int(commands[1])

    def get_id(self) -> int:
        return self.__circId

    def get_stream_id(self) -> int:
        return self.__streamId

    @staticmethod
    def compose_request(circId: int, stream_id: int) -> str:
        return f"{End.REQUEST_CODE}#{circId},{stream_id}"


class Teardown:
    REQUEST_CODE = 7

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 2)

        self.__circId = int(commands[0])
        self.__not_available_ip = commands[1]
        self.__port = int(commands[2])

    def get_id(self) -> int:
        return self.__circId

    def get_ip(self) -> str:
        return self.__not_available_ip

    def get_port(self) -> int:
        return self.__port

    @staticmethod
    def compose_request(circId: int, ip: str, port: int) -> str:
        return f"{Teardown.REQUEST_CODE}#{circId},{ip},{port}"


class Connected:
    REQUEST_CODE = 8

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 3)

        self.__circId = int(commands[0])
        self.__streamId = int(commands[1])
        self.__DH_handshake = int(commands[2])
        self.__key_hash = commands[3]

    def get_id(self) -> int:
        return self.__circId

    def get_stream_id(self) -> int:
        return self.__streamId

    def get_DH_handshake(self) -> int:
        return self.__DH_handshake

    def get_key_hash(self) -> str:
        return self.__key_hash

    @staticmethod
    def compose_response(circId: int, streamId: int, DH_handshake: int, key_hash: str) -> str:
        return f"{Connected.REQUEST_CODE}#{circId},{streamId},{DH_handshake},{key_hash}"


class Extend:
    REQUEST_CODE = 9

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 4)

        self.__circId = int(commands[0])
        self.__user_ip_and_port = commands[1]
        self.__p = int(commands[2])
        self.__g = int(commands[3])
        self.__RSA_DH_handshake = int(commands[4])

    def get_id(self) -> int:
        return self.__circId

    def get_user_ip_and_port(self) -> str:
        return self.__user_ip_and_port

    def get_dh_p(self) -> int:
        return self.__p

    def get_dh_g(self) -> int:
        return self.__g

    def get_RSA_DH_handshake(self) -> int:
        return self.__RSA_DH_handshake

    @staticmethod
    def compose_request(circId: int, ip_and_port: str, p: int, g: int, RSA_DH_handshake: int) -> str:
        return f"{Extend.REQUEST_CODE}#{circId},{ip_and_port},{p},{g},{RSA_DH_handshake}"


class Extended:
    REQUEST_CODE = 10

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 2)

        self.__circId = int(commands[0])
        self.__DH_handshake = int(commands[1])
        self.__key_hash = commands[2]

    def get_id(self) -> int:
        return self.__circId

    def get_DH_handshake(self) -> int:
        return self.__DH_handshake

    def get_key_hash(self) -> str:
        return self.__key_hash

    @staticmethod
    def compose_response(circId: int, DH_handshake: int, key_hash: str) -> str:
        return f"{Extended.REQUEST_CODE}#{circId},{DH_handshake},{key_hash}"


class Confirm:
    REQUEST_CODE = 11

    def __init__(self, command_str: str):
        commands = command_str.split('#', 1)[-1]
        commands = commands.split(',', 2)

        self.__circId = int(commands[0])
        self.__status = int(commands[1])
        self.__data = commands[2]

    def get_id(self) -> int:
        return self.__circId

    def get_data(self) -> str:
        return self.__data

    def get_status(self) -> int:
        return self.__status

    @staticmethod
    def compose_response(circId: int, status: int, data: str) -> str:
        return f"{Confirm.REQUEST_CODE}#{circId},{status},{data}"


# Functions
def get_command(request: str) -> int:
    request = request.split('#', 1)

    try:
        command = int(request[0])

        if Create.REQUEST_CODE <= command <= Confirm.REQUEST_CODE:
            return command

    except Exception:
        raise ValueError("Cannot decrypt data")

    return 0
