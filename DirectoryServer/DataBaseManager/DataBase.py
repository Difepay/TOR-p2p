# Imports
import sqlite3
import os
import random

from DataBaseUser import DataBaseUser


# Constants
BYTES_COUNT = 512

AVAILABLE = 1
NOT_AVAILABLE = 0


# Classes
class DataBase:
    """
    Class that gives management of the database file.
    Class provides functionality to add users, remove them, check password, and so on
    """

    # Static variables
    USERNAME_INDEX = 1
    PASSWORD_INDEX = 2

    IP_INDEX = 4
    PORT_INDEX = 5
    AVAILABLE_INDEX = 7

    def __init__(self, db_path: str):
        """
        Constructor of DataBase class. Initialize connection and cursor fields.
        Updates existing table or creates a new one \n
        :param db_path: path to the database file
        """
        self.__path = db_path
        self.__db_connection: sqlite3.Connection = None
        self.__db_cursor: sqlite3.Cursor = None

        DataBase.__create_if_not_exist_and_update(self.__path)

    @staticmethod
    def __create_if_not_exist_and_update(path: str) -> None:
        """
        Static method creates (if not exist) database file. Then close it and create (if not exist) users table.
        :param path: path to the database file to create or update
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file = open(path, 'a')
        file.close()

        connection = sqlite3.connect(path)
        cursor = connection.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key BLOB NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            allow_exit_node INTEGER NOT NULL,
            available INTEGER NOT NULL
        )''')

        #cursor.execute('''DELETE FROM users''')

        connection.commit()
        cursor.close()
        connection.close()

    def __open_connection(self) -> None:
        """
        Method that opens connection to the database
        """
        self.__db_connection = sqlite3.connect(self.__path)
        self.__db_cursor = self.__db_connection.cursor()

    def __close_connection(self) -> None:
        """
        Method that closes connection to the database
        """
        self.__db_connection.commit()
        self.__db_cursor.close()
        self.__db_connection.close()

    def get_users(self) -> list[tuple]:
        """
        Method that returns all users in database
        :return: list of all users in database (every user represented as a tuple)
        """
        self.__open_connection()

        self.__db_cursor.execute('SELECT * FROM users')
        users = self.__db_cursor.fetchall()

        self.__close_connection()

        return users

    def add_user(self, user: DataBaseUser) -> bool:
        """
        Methods adds new user into a database (if it possible)
        :param user: the instance of DataBaseUser to add it to the database
        :return: True - if succeed | else - False
        """
        if self.does_username_exists(user.get_username()):
            return False

        self.__open_connection()

        data_tuple = (
            user.get_username(), user.get_password(), sqlite3.Binary(user.get_public_key_n().to_bytes(BYTES_COUNT, "big")),
            user.get_ip(), user.get_port(), int(user.get_allow_exit_node()), AVAILABLE
        )

        self.__db_cursor.execute(
            f'INSERT INTO users (username, password, public_key, ip, port, allow_exit_node, available) VALUES (?, ?, ?, ?, ?, ?, ?)',
            data_tuple
        )

        self.__close_connection()
        return True

    def remove_user(self, username: str) -> None:
        """
        Method that removes user from the database
        :param username: the username to remove from the database
        """
        self.__open_connection()

        self.__db_cursor.execute(f'DELETE FROM users WHERE username = "{username}"')

        self.__close_connection()

    def is_password_valid(self, username: str, password: str) -> bool:
        """
        Method checks if there is user in database by username and given password
        :param username: the username of user to check
        :param password: the password of the user to check
        :return: True - if password math with username | else - False
        """
        self.__open_connection()

        self.__db_cursor.execute(f'SELECT * FROM users WHERE username = "{username}" AND password = "{password}"')
        data = self.__db_cursor.fetchall()

        self.__close_connection()

        # Username and password are correct
        return (data is not None) and (len(data) != 0)

    def does_username_exists(self, username: str):
        """
        Method checks if there is user with given username in database
        :param username: the username of user to check
        :return: True - if username exists | else - False
        """
        self.__open_connection()

        self.__db_cursor.execute(f'SELECT * FROM users WHERE username = "{username}"')
        data = self.__db_cursor.fetchall()

        self.__close_connection()

        # Username exists
        return (data is not None) and (len(data) != 0)

    def change_ip_and_port(self, username: str, new_port: int, new_ip: str) -> bool:
        """
        Method tries to change user's ip and port by given username
        :param username: the username of the user to change data
        :param new_port: new port of the user
        :param new_ip: new ip of the user
        :return: True - if succeed to change ip and port | else - False
        """
        if not self.does_username_exists(username):
            return False

        self.__open_connection()

        # Update the port and ip for the specified username
        self.__db_cursor.execute(f'UPDATE users SET port = {new_port}, ip = "{new_ip}" WHERE username = "{username}"')

        self.__close_connection()
        return True

    def change_rsa_public_key(self, user: DataBaseUser):
        self.__open_connection()

        rsa_key = user.get_public_key_n().to_bytes(BYTES_COUNT, "big")

        self.__db_cursor.execute(
            f'UPDATE users SET public_key = ? WHERE username = ? AND password = ?',
            (sqlite3.Binary(rsa_key), user.get_username(), user.get_password())
        )

        self.__close_connection()
        return True

    def change_availability(self, not_available_ip: str, port: int, available: int = 0) -> bool:
        """
        Method changes availability of the user that his ip is not available
        :param not_available_ip: ip of the not available user
        :param port: the port of the user
        :param available: available flag (0 - not available)
        :return: True - if succeed to change ip and port | else - False
        """
        self.__open_connection()

        # Update the availability for the specified ip
        self.__db_cursor.execute(f'UPDATE users SET available = {available} WHERE ip = "{not_available_ip}" AND port = {port}')

        self.__close_connection()
        return True

    def get_rsa_by_ip(self, ip: str, port: int) -> int:
        """
        Method gives rsa public key of the user with given ip and port
        :param ip: the ip of the user to get rsa public key
        :param port: the port of the user to get rsa public key
        :return: the rsa public key of the user by ip and port
        """
        self.__open_connection()

        self.__db_cursor.execute(f'SELECT public_key FROM users WHERE ip = "{ip}" AND port = {port}')
        public_key = int.from_bytes(self.__db_cursor.fetchone()[0], byteorder='big')

        self.__close_connection()
        return public_key

    def get_circuit(self, source_username: str, destination_username: str, nodes_count: int = 3) -> list[tuple[int, str, str, bytes, str, int, int, int]]:
        """
        Function generates circuit of users
        :param source_username: circuit from username
        :param destination_username: circuit to the target username
        :param nodes_count: nodes count in the circuit - default is 3
        :return: list of users to be in the circuit. [(id, username, password, key, ip, port, can_exit_node, available), ...]
        """
        original_users = self.get_users()

        # Remove source user of the users's list
        source_user = [user for user in original_users if user[DataBase.USERNAME_INDEX] == source_username][0]
        original_users.remove(source_user)

        # Remove destination user of the users's list
        destination_user = [user for user in original_users if user[DataBase.USERNAME_INDEX] == destination_username][0]
        original_users.remove(destination_user)

        if len(original_users) < nodes_count:
            # Error
            pass

        random.shuffle(original_users)
        return original_users[:nodes_count] + [destination_user]
