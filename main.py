import bcrypt
import os
from cryptography.fernet import Fernet
from typing import Dict, Optional
import boto3


class PasswordManager:
    def __init__(self, master_password: str):
        self.master_password = master_password.encode('utf-8')
        self.salt = bcrypt.gensalt()
        self.key = bcrypt.hashpw(self.master_password, self.salt)
        self.fernet = Fernet(self.key)

    def add_password(self, name: str, password: str):
        password_bytes = password.encode('utf-8')
        encrypted_password = self.fernet.encrypt(password_bytes)
        with open("passwords.txt", "a") as f:
            f.write(name + "|" + encrypted_password.decode('utf-8') + "\n")

    def get_password(self, name: str) -> Optional[str]:
        with open("passwords.txt", "r") as f:
            for line in f.readlines():
                data = line.rstrip()
                user, password = data.split("|")
                if user == name:
                    decrypted_password_bytes = self.fernet.decrypt(password.encode('utf-8'))
                    return decrypted_password_bytes.decode('utf-8')
        return None


def get_password_manager(master_password: str) -> PasswordManager:
    return PasswordManager(master_password)


def add_password(name: str, password: str, password_manager: PasswordManager):
    password_manager.add_password(name, password)


def get_password(name: str, password_manager: PasswordManager) -> Optional[str]:
    return password_manager.get_password(name)


if __name__ == "__main__":
    master_password = input("Enter your master password: ")
    password_manager = get_password_manager(master_password)

    while True:
        mode = input("Would you like to add or view passwords (add/view)? Press Q to quit: ").lower()
        if mode == "q":
            break

        if mode == "view":
            name = input("Enter the name of the account: ")
            password = get_password(name, password_manager)
            if password is None:
                print("Password not found.")
            else:
                print("Password:", password)

        elif mode == "add":
            name = input("Enter the name of the account: ")
            password = input("Enter the password: ")
            add_password(name, password, password_manager)

        else:
            print("Invalid mode.")
            continue
