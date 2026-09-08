"""Pure in-memory terminal. Never opens host files or runs processes."""
import posixpath
import shlex


class VirtualShell:
    def __init__(self):
        self.cwd = "/root"
        self.files = {
            "/etc/hostname": "edge-node\n",
            "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04 LTS"\n',
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "/root/readme.txt": "Maintenance node\n",
            "/var/log/auth.log": "",
        }
        self.directories = {"/", "/root", "/etc", "/var", "/var/log", "/tmp", "/home", "/bin"}

    def execute(self, text):
        try:
            words = shlex.split(text)
        except ValueError:
            return "sh: syntax error\n", 2
        if not words:
            return "", 0
        command, *args = words
        path = lambda value: posixpath.normpath(posixpath.join(self.cwd, value))
        fixed = {"pwd": self.cwd, "whoami": "root", "id": "uid=0(root) gid=0(root) groups=0(root)",
                 "hostname": "edge-node", "uname": "Linux edge-node 5.15.0-generic x86_64 GNU/Linux"}
        if command in fixed:
            return fixed[command] + "\n", 0
        if command == "echo":
            return " ".join(args) + "\n", 0
        if command == "cd":
            dest = path(args[0] if args else "/root")
            if dest not in self.directories:
                return "cd: No such directory\n", 1
            self.cwd = dest
            return "", 0
        if command == "ls":
            dest = path(next((arg for arg in args if not arg.startswith("-")), "."))
            if dest not in self.directories:
                return "ls: No such directory\n", 1
            items = sorted({posixpath.basename(p) for p in self.files.keys() | self.directories
                            if p != dest and posixpath.dirname(p) == dest})
            return "  ".join(items) + "\n", 0
        if command == "cat":
            return "".join(self.files.get(path(arg), "cat: No such file\n") for arg in args), 0
        if command in {"wget", "curl", "scp", "sftp"}:
            return "Network transfer unavailable\n", 1
        return f"{command[:100]}: command not found\n", 127
