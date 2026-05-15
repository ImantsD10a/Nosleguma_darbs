import json
import os
import hashlib
import secrets
import time
from datetime import datetime


# user class
class User:
    def __init__(self, username, salt, password_hash,
                 created_at=None, last_login=None,
                 failed_attempts=0, last_fail_ts=None, locked_until=0):

        self.username = username
        self.salt = salt
        self.password_hash = password_hash
        self.created_at = created_at or datetime.now().isoformat()
        self.last_login = last_login

        self.failed_attempts = failed_attempts
        self.last_fail_ts = last_fail_ts
        self.locked_until = locked_until

    def to_dict(self):
        return {
            "username": self.username,
            "salt": self.salt,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "failed_attempts": self.failed_attempts,
            "last_fail_ts": self.last_fail_ts,
            "locked_until": self.locked_until
        }

    @staticmethod
    def from_dict(data):
        return User(
            data["username"],
            data["salt"],
            data["password_hash"],
            data.get("created_at"),
            data.get("last_login"),
            data.get("failed_attempts", 0),
            data.get("last_fail_ts"),
            data.get("locked_until", 0)
        )


# storage class
class Storage:
    FILE_NAME = "users.json"

    @staticmethod
    def load_users():
        if not os.path.exists(Storage.FILE_NAME):
            return {}

        with open(Storage.FILE_NAME, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {u: User.from_dict(info) for u, info in data.items()}

    @staticmethod
    def save_users(users):
        with open(Storage.FILE_NAME, "w", encoding="utf-8") as f:
            json.dump({u: user.to_dict() for u, user in users.items()}, f, indent=4)


# auth service
class AuthService:

    def __init__(self):
        self.users = Storage.load_users()

    def _hash_password(self, password, salt):
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def _log(self, username, status):
        with open("auth.log", "a", encoding="utf-8") as f:
            t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{t} | {username} | {status}\n")

    # risk calc
    def _calculate_risk(self, user, username, password):

        risk = 0
        reasons = []

        if user:
            risk += 20 * user.failed_attempts
            if user.failed_attempts > 0:
                reasons.append(f"{user.failed_attempts} fail")

        if len(password) < 6:
            risk += 25
            reasons.append("īsa parole")

        if not user:
            risk += 40
            reasons.append("nezināms lietotājs")

        if user and user.last_fail_ts:
            if time.time() - user.last_fail_ts < 10:
                risk += 15
                reasons.append("ātri mēģinājumi")

        return risk, reasons

    def _get_lockout(self, risk):

        if risk < 40:
            return 0
        elif risk < 80:
            return 30
        else:
            return 120

    # reģistrācija
    def register(self, username, password):

        if username in self.users:
            print("Lietotājs jau eksistē")
            return

        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)

        user = User(username, salt, password_hash)

        self.users[username] = user
        Storage.save_users(self.users)

        print("Reģistrācija veiksmīga")

    # login
    def login(self, username, password):

        user = self.users.get(username)

        if user and time.time() < user.locked_until:
            wait = int(user.locked_until - time.time())
            print(f"Konts bloķēts vēl {wait} sekundes")
            return None

        risk, reasons = self._calculate_risk(user, username, password)
        lockout = self._get_lockout(risk)

        if user:
            password_hash = self._hash_password(password, user.salt)

            if password_hash == user.password_hash:

                user.failed_attempts = 0
                user.last_login = datetime.now().isoformat()

                Storage.save_users(self.users)

                self._log(username, "SUCCESS")

                print("Login successful")

                return user

        # fail
        if user:
            user.failed_attempts += 1
            user.last_fail_ts = time.time()
            user.locked_until = time.time() + lockout

        Storage.save_users(self.users)

        self._log(username, "FAIL")

        print("Login failed")
        print(f"Risk: {risk} ({', '.join(reasons)}) → Lockout: {lockout}s")

        return None


# main menu
def main():

    auth = AuthService()
    logged_user = None

    while True:

        if not logged_user:

            print("\nLogin sistēma (Izvēlies ciparu)")
            print("1. Register")
            print("2. Login")
            print("3. Exit")

            choice = input("Izvēle: ")

            if choice == "1":
                username = input("Username: ")
                password = input("Password: ")

                auth.register(username, password)

            elif choice == "2":
                username = input("Username: ")
                password = input("Password: ")

                logged_user = auth.login(username, password)

            elif choice == "3":
                print("Uzredzēšanos!")
                break

        else:

            print("\nProfile")
            print("Username:", logged_user.username)
            print("Created:", logged_user.created_at)
            print("Last login:", logged_user.last_login)

            print("1. Logout")

            choice = input("Izvēle: ")

            if choice == "1":
                logged_user = None


if __name__ == "__main__":
    main()
