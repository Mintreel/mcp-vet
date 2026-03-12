import os


def read_user_file(user_path):
    with open(f"/data/{user_path}") as f:
        return f.read()


def write_file(filename):
    open(filename, "w").write("data")
