from impacket.ldap import ldapasn1 as ldapasn1_impacket

class NXCModule:
    """
    Find GPO associated OU

    Module by @KlemouLeZoZo
    """

    name = "gpo_resolver"
    description = "Find GPO associated OU"
    supported_protocols = ['ldap']  
    opsec_safe = True  
    multiple_hosts = False 

    def __init__(self):
        self.context           = None
        self.module_options    = None
        self.guid              = None
        self.clean_ldap_result = lambda results : [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
    
    def options(self, context, module_options):
        """
        GUID        GPO GUID example:{6AC1786C-016F-11D2-945F-00C04fB984F9}
        """

        if "GUID" not in module_options:
            context.log.fail("GUID option not specified!")
            exit(1)

        if len(module_options["GUID"]) != 38:
            context.log.fail("Invalid value for GUID option! (example: {6AC1786C-016F-11D2-945F-00C04fB984F9})")
            exit(1)

        self.guid = module_options["GUID"]

    def on_login(self, context, connection):
        """Concurrent.
        Required if on_admin_login is not present. This gets called on each authenticated connection
        """

        context.log.display("Getting the MachineAccountQuota")

        results      = self.clean_ldap_result( connection.search(f"(name={self.guid})", ["displayName"]) )
        display_name = ""

        if len(results) == 0:
            context.log.error(f"{self.guid} Not Found")
            return
            
        display_name = str(results[0]["attributes"][0]["vals"][0])

        results = self.clean_ldap_result( connection.search(f"(gpLink=*{self.guid}*)", [""]) )
        
        if len(results) == 0:
            context.log.error(f"{display_name} No GpLink Found")
            return
        
        for i in range(len(results)):

            dn = str(results[i]["objectName"])
            if i == 0:
                context.log.highlight(f"{display_name} : {dn}")
            else:
                context.log.highlight(f"{' '*len(display_name)} : {dn}")