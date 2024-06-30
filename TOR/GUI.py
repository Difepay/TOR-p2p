import threading

import dearpygui.dearpygui as dpg
from User import User
from tkinter import messagebox


SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600


class App:
    def __init__(self):
        self.chat_title = None
        self.current_username: str = ""

        self.user: User = None
        self.__circuits: dict[str, str] = {}

        self.setup_ui()

    def setup_ui(self):
        dpg.create_context()

        with dpg.window(tag="Main Window", width=SCREEN_WIDTH, height=SCREEN_HEIGHT, no_resize=True):
            dpg.add_text("Main Window - temporary account")

            self.username_entry = dpg.add_input_text(hint="Enter username")
            self.password_entry = dpg.add_input_text(hint="Enter password", password=True)
            self.port_entry = dpg.add_input_text(hint="Enter port")

            dpg.add_button(label="Create an account", callback=self.handle_create_account)

            self.main_wait_text = dpg.add_text('Wait for the keys generating...')
            dpg.hide_item(self.main_wait_text)

        with dpg.window(tag="Construct Window", show=False, width=SCREEN_WIDTH, height=SCREEN_HEIGHT, no_resize=True):
            dpg.add_text("Construct window - enter username to construct circuit with him")

            self.construct_username_entry = dpg.add_input_text(hint="Enter username")

            dpg.add_button(label="Construct Circuit", callback=self.handle_construct_circuit)

            self.construct_wait_text = dpg.add_text('Wait for the circuit creation...')
            dpg.hide_item(self.construct_wait_text)

            dpg.add_text("Users with already constructed circuits:")
            # Create a group for dynamically adding buttons
            self.dynamic_button_group = dpg.add_group()

            dpg.add_button(label="Exit", callback=self.exit)

        with dpg.window(tag="Chat Window", show=False, width=SCREEN_WIDTH, height=SCREEN_HEIGHT, no_resize=True):
            self.chat_title = dpg.add_text(label="Chat Window - ")
            self.current_username = ""

            self.message_entry = dpg.add_input_text(hint="Enter message to send")
            dpg.add_button(label="Send", callback=self.handle_send_data)

            dpg.add_button(label="Back to chats", callback=self.back_to_chats)
            dpg.add_button(label="Exit", callback=self.exit)

        dpg.create_viewport(title='TOR', width=SCREEN_WIDTH, height=SCREEN_HEIGHT, resizable=False)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("Main Window", True)

    def exit(self):
        if self.user is not None:
            self.user.destroy()

        exit(0)

    def handle_create_account(self):
        entered_username = dpg.get_value(self.username_entry)
        entered_password = dpg.get_value(self.password_entry)
        entered_port = dpg.get_value(self.port_entry)

        try:
            entered_port = int(entered_port)

            if not 1 <= entered_port <= 2**16:
                messagebox.showinfo('Create Account Status', f'Port must be at range: 1 -> {2**16}')
                return

        except ValueError:
            messagebox.showinfo('Create Account Status', 'Port must be an integer!')
            return

        # Create a user
        try:
            dpg.show_item(self.main_wait_text)
            self.user = User(entered_port, entered_username, entered_password)
            dpg.hide_item(self.main_wait_text)

        except ...:
            messagebox.showinfo('Create Account Status', f'Currently someone uses your username: {entered_username}')
            self.user = None
            return

        dpg.hide_item("Main Window")
        dpg.show_item("Construct Window")

        dpg.set_primary_window("Main Window", False)
        dpg.set_primary_window("Construct Window", True)

        dpg.set_viewport_title(f'TOR. Logged as: {entered_username}')

        server_thread = threading.Thread(target=self.check_for_messages)
        server_thread.daemon = True
        server_thread.start()

    def handle_construct_circuit(self):
        entered_target_username = dpg.get_value(self.construct_username_entry)

        if (entered_target_username is None) or (len(entered_target_username) == 0):
            return

        dpg.show_item(self.construct_wait_text)
        address_of_the_target = self.user.construct_circuit(entered_target_username)
        dpg.hide_item(self.construct_wait_text)

        if self.__circuits.get(entered_target_username) != address_of_the_target:
            self.__circuits[entered_target_username] = address_of_the_target
            dpg.add_button(label=f"Circuit with: {entered_target_username}", parent=self.dynamic_button_group, callback=self.handle_to_chat, tag=entered_target_username)

    def handle_to_chat(self, sender):
        dpg.hide_item("Construct Window")
        dpg.show_item("Chat Window")

        dpg.set_primary_window("Construct Window", False)
        dpg.set_primary_window("Chat Window", True)

        self.current_username = dpg.get_item_label(sender).split(': ')[1]
        dpg.set_value(self.chat_title, f"Chat window: {self.current_username}")

    def handle_send_data(self):
        entered_data = dpg.get_value(self.message_entry)

        if (entered_data is None) or (len(entered_data) == 0):
            return

        self.user.send_data(entered_data, self.__circuits[self.current_username])

    def back_to_chats(self):
        self.current_username = ""

        dpg.hide_item("Chat Window")
        dpg.show_item("Construct Window")

        dpg.set_primary_window("Chat Window", False)
        dpg.set_primary_window("Construct Window", True)

    def check_for_messages(self):
        while True:
            data = self.user.check_for_received_data()

            if not isinstance(data, tuple):
                continue

            messagebox.showinfo(f'Data Receive - {self.user.get_username()}', f'circuit id: {data[0]}\nstream id: {data[1]}\nmessage: {data[2]}\n')


# Run statement
if __name__ == '__main__':
    app = App()
    dpg.start_dearpygui()
    dpg.destroy_context()
