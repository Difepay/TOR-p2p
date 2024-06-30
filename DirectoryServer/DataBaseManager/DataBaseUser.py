# Classes
class DataBaseUser:
    """
    Class represents database user (just filled with database fields)
    """

    def __init__(self, arguments: str):
        """
        Constructor - creates user instance from given string, where every item
        separated by ', and represents database table column
        """
        parameters = arguments.split(',')

        self.__username = parameters[0]
        self.__password = parameters[1]

        self.__public_key_exponent = int(parameters[2])
        self.__public_key_n = int(parameters[3])

        self.__ip = parameters[4]
        self.__port = int(parameters[5])

        self.__allow_exit_node = bool(int(parameters[6]))

    def get_username(self) -> str:
        """
        Getter for user's username
        :return: user's username
        """
        return self.__username

    def get_password(self) -> str:
        """
        Getter for user's password (hashed)
        :return: user's password (hashed)
        """
        return self.__password

    def get_public_key_exponent(self) -> int:
        """
        Getter for user's rsa public key exponent (just a constant, not used)
        :return: user's rsa public key exponent
        """
        return self.__public_key_exponent

    def get_public_key_n(self) -> int:
        """
        Getter for user's rsa public key n number
        :return: user's rsa public key n number
        """
        return self.__public_key_n

    def get_ip(self) -> str:
        """
        Getter for user's ip
        :return: user's  ip
        """
        return self.__ip

    def get_port(self) -> int:
        """
        Getter for user's port
        :return: user's port
        """
        return self.__port

    def get_allow_exit_node(self) -> bool:
        """
        Getter for flag - if user can allow to be exit node
        :return: allow exit node flag
        """
        return self.__allow_exit_node
