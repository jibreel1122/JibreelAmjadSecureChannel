import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)


def launch(script_name):
    script_path = os.path.join(HERE, script_name)
    env = dict(os.environ)
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.Popen([sys.executable, script_path], cwd=PROJECT_ROOT, env=env)


if __name__ == "__main__":
    print("starting server and client guis by jibreel bornat 2026")

    server_proc = launch("j_server_gui.py")
    client_proc = launch("j_gui.py")

    server_proc.wait()
    client_proc.wait()

    print("both guis closed")
