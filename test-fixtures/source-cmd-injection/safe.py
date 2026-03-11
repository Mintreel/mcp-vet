import subprocess

def safe_clone():
    subprocess.run(['git', 'clone', 'https://github.com/example/repo.git'], check=True)
