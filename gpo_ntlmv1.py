from io import BytesIO

class NXCModule:
    """
    Find which GPO enbale NTLMv1 usage

    Module by @KlemouLeZoZo
    """

    name = "gpo_ntlmv1"
    description = "Find which GPO enbale NTLMv1 usage"
    supported_protocols = ['smb']  
    opsec_safe = True  
    multiple_hosts = True  

    def __init__(self):
        self.context        = None
        self.module_options = None
        self.key_name       = "LmCompatibilityLevel"

    def options(self, context, module_options):
        """
        """
        pass

    def on_login(self, context, connection):
        """Concurrent.
        Required if on_admin_login is not present. This gets called on each authenticated connection
        """

        shares = connection.shares()
        for share in shares:
            if share["name"] == "SYSVOL" and "READ" in share["access"]:
                context.log.success("Found SYSVOL share")
                context.log.display(f"Searching for {self.key_name} related GPO")

                paths = connection.spider(
                    "SYSVOL",
                    pattern=[
                        "GptTmpl.inf",
                    ],
                )

                for path in paths:
                    gpo_id = path.split('/')[2]
                    buf    = BytesIO()

                    connection.conn.getFile("SYSVOL", path, buf.write)
                    file_content = buf.getvalue().decode("utf16")
                    if (index:=file_content.find(self.key_name)) != -1:
                        
                        hive_value = file_content[index+len(self.key_name):].replace(" ","").replace("=","").split("\r\n")[0] #remove space and = and take firstline

                        if hive_value.count(",") != 1:
                            raise Exception("Invalide hive value")

                        _, value = hive_value.split(",")

                        if not value.isnumeric():
                            raise Exception("Invalide hive value")

                        if int(value) < 3:
                            context.log.highlight(f"{gpo_id} enable NTLMv1 usage")
