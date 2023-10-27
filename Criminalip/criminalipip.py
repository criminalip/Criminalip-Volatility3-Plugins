# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


__version__ = "1.0.0"

from datetime import datetime, timedelta
from dateutil.parser import parse
import os,requests,sys,ipaddress,logging
from typing import Iterable, List, Optional, Tuple, Type
import sqlite3
from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import network
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, poolscanner, verinfo
from volatility3.plugins.Criminalip.db_insert_modul import table_insert_ip




API_KEY = '${CRIMINALIP_API_KEY}'

vollog = logging.getLogger(__name__)

class NetworkConnections(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Displays network connections"""
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="verinfo", component=verinfo.VerInfo, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="include-corrupt",
                description="Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='malIP',
                description='This is an option that only outputs risky IPs',
                default=False,
                optional=True
            )
        ]

    @staticmethod
    def create_netscan_constraints(
        context: interfaces.context.ContextInterface, symbol_table: str
    ) -> List[poolscanner.PoolConstraint]:
        """Creates a list of Pool Tag Constraints for network objects.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the symbols / types

        Returns:
            The list containing the built constraints.
        """

        tcpl_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_TCP_LISTENER"
        ).size
        tcpe_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_TCP_ENDPOINT"
        ).size
        udpa_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_UDP_ENDPOINT"
        ).size

        # ~ vollog.debug("Using pool size constraints: TcpL {}, TcpE {}, UdpA {}".format(tcpl_size, tcpe_size, udpa_size))

        return [
            # TCP listener
            poolscanner.PoolConstraint(
                b"TcpL",
                type_name=symbol_table + constants.BANG + "_TCP_LISTENER",
                size=(tcpl_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
            # TCP Endpoint
            poolscanner.PoolConstraint(
                b"TcpE",
                type_name=symbol_table + constants.BANG + "_TCP_ENDPOINT",
                size=(tcpe_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
            # UDP Endpoint
            poolscanner.PoolConstraint(
                b"UdpA",
                type_name=symbol_table + constants.BANG + "_UDP_ENDPOINT",
                size=(udpa_size, None),
                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
            ),
        ]

    @classmethod
    def determine_tcpip_version(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbol_table: str,
    ) -> Tuple[str, Type]:
        """Tries to determine which symbol filename to use for the image's tcpip driver. The logic is partially taken from the info plugin.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols

        Returns:
            The filename of the symbol table to use.
        """

        # while the failsafe way to determine the version of tcpip.sys would be to
        # extract the driver and parse its PE header containing the versionstring,
        # unfortunately that header is not guaranteed to persist within memory.
        # therefore we determine the version based on the kernel version as testing
        # with several windows versions has showed this to work out correctly.

        is_64bit = symbols.symbol_table_is_64bit(context, nt_symbol_table)

        is_18363_or_later = versions.is_win10_18363_or_later(
            context=context, symbol_table=nt_symbol_table
        )

        if is_64bit:
            arch = "x64"
        else:
            arch = "x86"

        vers = info.Info.get_version_structure(context, layer_name, nt_symbol_table)

        kuser = info.Info.get_kuser_structure(context, layer_name, nt_symbol_table)

        try:
            vers_minor_version = int(vers.MinorVersion)
            nt_major_version = int(kuser.NtMajorVersion)
            nt_minor_version = int(kuser.NtMinorVersion)
        except ValueError:
            # vers struct exists, but is not an int anymore?
            raise NotImplementedError(
                "Kernel Debug Structure version format not supported!"
            )
        except:
            # unsure what to raise here. Also, it might be useful to add some kind of fallback,
            # either to a user-provided version or to another method to determine tcpip.sys's version
            raise exceptions.VolatilityException(
                "Kernel Debug Structure missing VERSION/KUSER structure, unable to determine Windows version!"
            )

        vollog.debug(
            "Determined OS Version: {}.{} {}.{}".format(
                kuser.NtMajorVersion,
                kuser.NtMinorVersion,
                vers.MajorVersion,
                vers.MinorVersion,
            )
        )

        if nt_major_version == 10 and arch == "x64":
            # win10 x64 has an additional class type we have to include.
            class_types = network.win10_x64_class_types
        else:
            # default to general class types
            class_types = network.class_types

        # these versions are listed explicitly because symbol files differ based on
        # version *and* architecture. this is currently the clearest way to show
        # the differences, even if it introduces a fair bit of redundancy.
        # furthermore, it is easy to append new versions.
        if arch == "x86":
            version_dict = {
                (6, 0, 6000, 0): "netscan-vista-x86",
                (6, 0, 6001, 0): "netscan-vista-x86",
                (6, 0, 6002, 0): "netscan-vista-x86",
                (6, 0, 6003, 0): "netscan-vista-x86",
                (6, 1, 7600, 0): "netscan-win7-x86",
                (6, 1, 7601, 0): "netscan-win7-x86",
                (6, 1, 8400, 0): "netscan-win7-x86",
                (6, 2, 9200, 0): "netscan-win8-x86",
                (6, 3, 9600, 0): "netscan-win81-x86",
                (10, 0, 10240, 0): "netscan-win10-10240-x86",
                (10, 0, 10586, 0): "netscan-win10-10586-x86",
                (10, 0, 14393, 0): "netscan-win10-14393-x86",
                (10, 0, 15063, 0): "netscan-win10-15063-x86",
                (10, 0, 16299, 0): "netscan-win10-15063-x86",
                (10, 0, 17134, 0): "netscan-win10-17134-x86",
                (10, 0, 17763, 0): "netscan-win10-17134-x86",
                (10, 0, 18362, 0): "netscan-win10-17134-x86",
                (10, 0, 18363, 0): "netscan-win10-17134-x86",
            }
        else:
            version_dict = {
                (6, 0, 6000, 0): "netscan-vista-x64",
                (6, 0, 6001, 0): "netscan-vista-sp12-x64",
                (6, 0, 6002, 0): "netscan-vista-sp12-x64",
                (6, 0, 6003, 0): "netscan-vista-sp12-x64",
                (6, 1, 7600, 0): "netscan-win7-x64",
                (6, 1, 7601, 0): "netscan-win7-x64",
                (6, 1, 8400, 0): "netscan-win7-x64",
                (6, 2, 9200, 0): "netscan-win8-x64",
                (6, 3, 9600, 0): "netscan-win81-x64",
                (6, 3, 9600, 19935): "netscan-win81-19935-x64",
                (10, 0, 10240, 0): "netscan-win10-x64",
                (10, 0, 10586, 0): "netscan-win10-x64",
                (10, 0, 14393, 0): "netscan-win10-x64",
                (10, 0, 15063, 0): "netscan-win10-15063-x64",
                (10, 0, 16299, 0): "netscan-win10-16299-x64",
                (10, 0, 17134, 0): "netscan-win10-17134-x64",
                (10, 0, 17763, 0): "netscan-win10-17763-x64",
                (10, 0, 18362, 0): "netscan-win10-18362-x64",
                (10, 0, 18363, 0): "netscan-win10-18363-x64",
                (10, 0, 19041, 0): "netscan-win10-19041-x64",
            }

        # we do not need to check for tcpip's specific FileVersion in every case
        tcpip_mod_version = 0  # keep it 0 as a default

        # special use cases

        # Win10_18363 is not recognized by windows.info as 18363
        # because all kernel file headers and debug structures report 18363 as
        # "10.0.18362.1198" with the last part being incremented. However, we can use
        # os_distinguisher to differentiate between 18362 and 18363
        if vers_minor_version == 18362 and is_18363_or_later:
            vollog.debug(
                "Detected 18363 data structures: working with 18363 symbol table."
            )
            vers_minor_version = 18363

        # we need to define additional version numbers (which are then found via tcpip.sys's FileVersion header) in case there is
        # ambiguity _within_ an OS version. If such a version number (last number of the tuple) is defined for the current OS
        # we need to inspect tcpip.sys's headers to see if we can grab the precise version
        if [
            (a, b, c, d)
            for a, b, c, d in version_dict
            if (a, b, c) == (nt_major_version, nt_minor_version, vers_minor_version)
            and d != 0
        ]:
            vollog.debug(
                "Requiring further version inspection due to OS version by checking tcpip.sys's FileVersion header"
            )
            # the following is IntelLayer specific and might need to be adapted to other architectures.
            physical_layer_name = context.layers[layer_name].config.get(
                "memory_layer", None
            )
            if physical_layer_name:
                ver = verinfo.VerInfo.find_version_info(
                    context, physical_layer_name, "tcpip.sys"
                )
                if ver:
                    tcpip_mod_version = ver[3]
                    vollog.debug(
                        "Determined tcpip.sys's FileVersion: {}".format(
                            tcpip_mod_version
                        )
                    )
                else:
                    vollog.debug("Could not determine tcpip.sys's FileVersion.")
            else:
                vollog.debug(
                    "Unable to retrieve physical memory layer, skipping FileVersion check."
                )

        # when determining the symbol file we have to consider the following cases:
        # the determined version's symbol file is found by intermed.create -> proceed
        # the determined version's symbol file is not found by intermed -> intermed will throw an exc and abort
        # the determined version has no mapped symbol file -> if win10 use latest, otherwise throw exc
        # windows version cannot be determined -> throw exc

        filename = version_dict.get(
            (nt_major_version, nt_minor_version, vers_minor_version, tcpip_mod_version)
        )
        if not filename:
            # no match on filename means that we possibly have a version newer than those listed here.
            # try to grab the latest supported version of the current image NT version. If that symbol
            # version does not work, support has to be added manually.
            current_versions = [
                (nt_maj, nt_min, vers_min, tcpip_ver)
                for nt_maj, nt_min, vers_min, tcpip_ver in version_dict
                if nt_maj == nt_major_version
                and nt_min == nt_minor_version
                and tcpip_ver <= tcpip_mod_version
            ]
            current_versions.sort()

            if current_versions:
                latest_version = current_versions[-1]

                filename = version_dict.get(latest_version)

                vollog.debug(
                    f"Unable to find exact matching symbol file, going with latest: {filename}"
                )

            else:
                raise NotImplementedError(
                    "This version of Windows is not supported: {}.{} {}.{}!".format(
                        nt_major_version,
                        nt_minor_version,
                        vers.MajorVersion,
                        vers_minor_version,
                    )
                )

        vollog.debug(f"Determined symbol filename: {filename}")

        return filename, class_types
    
    @classmethod
    def create_netscan_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for TCP Listeners and TCP/UDP Endpoints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols
            config_path: The config path where to find symbol files

        Returns:
            The name of the constructed symbol table
        """
        table_mapping = {"nt_symbols": nt_symbol_table}

        symbol_filename, class_types = cls.determine_tcpip_version(
            context,
            layer_name,
            nt_symbol_table,
        )

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            os.path.join("windows", "netscan"),
            symbol_filename,
            class_types=class_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def scan(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbol_table: str,
        netscan_symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for network objects using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols
            netscan_symbol_table: The name of the table containing the network object symbols (_TCP_LISTENER etc.)

        Returns:
            A list of network objects found by scanning the `layer_name` layer for network pool signatures
        """

        constraints = cls.create_netscan_constraints(context, netscan_symbol_table)

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, nt_symbol_table, constraints
        ):
            _constraint, mem_object, _header = result
            
            yield mem_object
    
    '''
    The following is a function used to retrieve results for a foreign IP using the Criminal IP API:
    - It retrieves the tag value, and if there are no Snort-related tags, the IDS value is set to "N/A."
                                           And if there are Snort-related tags, it retrieves all the classification values associated with the existing IDS content. 
    - It retrieves the product name and version of the related domains by querying the current port and its history within the last 30 days.
    - It also provides the score, representative information, and abuse information for the current IP.
    - Please note that if all credits are exhausted, the function may display a notification message about credit depletion and close the operation window.
    
    '''
    
    def get_ip_data(ip,port):
        headers = {"x-api-key": API_KEY}
        payload = {}
        response = requests.request("GET",f"https://api.criminalip.io/v1/feature/ip/suspicious-info?ip={ip}",headers=headers,data=payload)

        try:
            now = datetime.now()
            thirty_days_ago = now - timedelta(days=30)
            json_response = response.json()
            
            try:
                tagList = []
                for key,value in json_response["issues"].items():
                    if value:
                        tag = key.replace("is_","").strip()
                        tagList.append(tag)
                tagString = ','.join(tagList)
            except KeyError:
                tagString = "No data available"
            
            if "snort" in tagList:
                ids_data = json_response.get("ids", {}).get("data", [])
                if ids_data:
                    classificationList = [ids_dict.get("classification", "") for ids_dict in ids_data]
                    classificationString = ",".join(classificationList)
                else:
                    classificationString = "No data available"
            else:
                classificationString = "N/A"

            try:
                inbound = json_response["score"]["inbound"]
                outbound = json_response["score"]["outbound"]
            except KeyError:
                inbound = "N/A"
                outbound = "N/A"
    
            target_data = None
            min_time_diff = timedelta.max
                       
            
            for item in json_response["current_opened_port"]["data"]:
                
                if item["port"] == port:
                    confirmed_time = parse(item["confirmed_time"])
                    time_diff = abs(now - confirmed_time)
                    if time_diff < min_time_diff and confirmed_time >= thirty_days_ago and item["port"] == port:
                        target_data = item
                        min_time_diff = time_diff
            
                     

            if target_data:
                product = target_data.get("product_name","Not available")
                version = target_data.get("product_version","-")
            else:
                product = "N/A"
                version = "-"

            result = {
                "port":port,
                "app": product + '/' + version,
                "inbound_outbound": inbound + '/' + outbound,
                "tags": tagString,
                "representative": json_response["representative_domain"],
                "ids": classificationString,
                "abuse": json_response["abuse_record_count"],
                "check" :  'N/A',
                "verification" : None
            }

            return result

        except Exception as e:
            if str(e) == "limit exceeded":
                print("API limit exceeded")
            else:
                print(f"\nError occurred: {e}")
            sys.exit(1)

           

    '''
     Based on the results obtained from the function, it scores each result and if it is above 3, it is considered a risk and shows the malIP option.

    '''
    def malipChecking(ip,port):
        checkscore = None 
        check = 0
        ip_data = NetworkConnections.get_ip_data(ip,port)

        tagString = ip_data.get("tags", "")
        inbound_outbound = ip_data.get("inbound_outbound", "")
        inbound, outbound = inbound_outbound.split("/")

        if inbound == "moderate" or outbound == "moderate":
            if outbound == "dangerous" or outbound == "critical":
                check += 2
            check += 1
            
        if tagString:
            tagList = tagString.split(",")
            if len(tagList) > 0:
                check += 1
        if ip_data.get("ids") != "No data available" or ip_data.get("ids") != 'N/A':
            check += 1
        if ip_data.get("representative") is None:
            check += 1
        if ip_data.get("abuse", 0) > 0:
            check += 2

        if check == 0:
            checkscore = "safe"
        elif check <= 3:
            checkscore = 'moderate'
        elif check > 3:
            checkscore = "critical"
            
        result = {
            "port":port,
            "app": ip_data.get("app"),
            "inbound_outbound": ip_data.get("inbound_outbound", ""),
            "tags": ip_data.get("tags", ""),
            "representative": ip_data.get("representative"),
            "ids": ip_data.get("ids"),
            "abuse":ip_data.get("abuse"),
            "verification" :  checkscore
        }

        return result


    '''
   This function determines whether a given IP address is a public IP. 
    '''
    def is_private_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
        
     
    '''
    This function extracts information about the IP and determines whether the options are used to return the results.

    It also collects various information based on the provided IP address and helps identify specific details related to the IP. Additionally, 
    it checks the usage of options and includes the corresponding results in the returned output for the user.
    '''   
                        
    def _generator(self,conn,cursor, malip,show_corrupt_results: Optional[bool] = None):
        
        
        """Generates the network objects for use in rendering."""
        kernel = self.context.modules[self.config["kernel"]]

        netscan_symbol_table = self.create_netscan_symbol_table(
            self.context, kernel.layer_name, kernel.symbol_table_name, self.config_path
        )
        # NetworkConnections.check_and_create_table(conn,cursor)    
        for netw_obj in self.scan(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            netscan_symbol_table,
        ):
            vollog.debug(
                f"Found netw obj @ 0x{netw_obj.vol.offset:2x} of assumed type {type(netw_obj)}"
            )
            # objects passed pool header constraints. check for additional constraints if strict flag is set.
            if not show_corrupt_results and not netw_obj.is_valid():
                continue
            
            
            
            if isinstance(netw_obj, network._TCP_ENDPOINT):
                vollog.debug(f"Found _TCP_ENDPOINT @ 0x{netw_obj.vol.offset:2x}")
                if netw_obj.get_address_family() == network.AF_INET:
                    proto = "TCPv4"
                elif netw_obj.get_address_family() == network.AF_INET6:
                    proto = "TCPv6"
                else:
                    proto = "TCPv?"
                
                owner_pid = str(netw_obj.get_owner_pid()) or str(renderers.UnreadableValue())    
                procname =str(netw_obj.get_owner_procname()) or str(renderers.UnreadableValue())
                local = netw_obj.get_local_address() or renderers.UnreadableValue() 
            
                if isinstance(local, renderers.UnreadableValue):
                    localaddr = str(local)
                else:
                    localaddr = local+ ':' +str(netw_obj.LocalPort)
                
                foreign = netw_obj.get_remote_address() or renderers.UnreadableValue()
                if isinstance(foreign, renderers.UnreadableValue):
                    foreign = None
 

                # verification = None
                if foreign == "127.0.0.1" or  NetworkConnections.is_private_ip(foreign) or foreign is None:
                    continue
                
                foreign_port = netw_obj.RemotePort   
                if  isinstance(foreign_port, renderers.UnreadableValue):
                    foreign_port = None   
                    
                foreignaddr = foreign+" :"+str(foreign_port) 
                
                cursor.execute("SELECT * FROM ips WHERE public_ip=? AND port=?", (foreign,foreign_port))
                duplicate_rows = cursor.fetchall()
                
                if duplicate_rows:
                    for row in duplicate_rows:
                        foreignaddr = row[0] +':'+ row[1]
                        app =  row[2]
                        inbound_outbound = row[3]
                        tags= row[4]
                        representative= row[5]
                        ids= row[6]
                        abuse= row[7]
                        verification= row[8]

                else: 
                    map = NetworkConnections.malipChecking(netw_obj.get_remote_address(),netw_obj.RemotePort)
                    if map is None: 
                        map = {}
                        map['port'] = renderers.UnreadableValue()
                        map["app"] = renderers.UnreadableValue()
                        map["inbound_outbound"] = renderers.UnreadableValue()
                        map["tags"] = renderers.UnreadableValue() 
                        map["representative"] = renderers.UnreadableValue() 
                        map["ids"] = renderers.UnreadableValue() 
                        map["abuse"] = renderers.UnreadableValue()
                        map["verification"] = renderers.UnreadableValue()
                
                    app = map['app']  
                    inbound_outbound = map['inbound_outbound']
                    tags = map['tags']
                    representative = map['representative']
                    ids = map['ids']
                    abuse = map['abuse']
                    verification = map['verification']
                    table_insert_ip(cursor, map, foreign,verification)
                    
                create_time = netw_obj.get_create_time() 
                if not isinstance(create_time, (renderers.UnparsableValue, renderers.NotApplicableValue)):
                    time_string = create_time.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    time_string = "None"

                if (malip and (verification == "critical")) or (not malip):
                    yield (
                        0,
                        (
                            "{:<19}".format(time_string or "-"),
                            "{:<10}".format(owner_pid),
                            "{:<16}".format(procname or "-"),
                            "{:<7}".format(proto),
                            "{:<15}".format(localaddr),
                            "{:<20}".format(foreignaddr),
                            "{:<22}".format(app or "-"),
                            "{:<22}".format(inbound_outbound or "-"),
                            "{:<22}".format(tags or "-"),
                            "{:<20}".format(representative or "-"),
                            "{:<10}".format(ids or "-"),
                            "{:<6}".format(str(abuse) or "-"),
                        ),
                    )
        conn.close()  
                             
    def generate_timeline(self):
                               
        for row in self._generator():
            _depth, row_data = row
            # Skip network connections without creation time
            if not isinstance(row_data[9], datetime.datetime):
                continue
            row_data = [
                "N/A"
                if isinstance(i, renderers.UnreadableValue)
                or isinstance(i, renderers.UnparsableValue)
                else i
                for i in row_data
            ]
            description = (
                "Network connection: Process {} {} Local Address {}:{} "
                "Remote Address {}:{} State {} Protocol {} ".format(
                    row_data[7],
                    row_data[8],
                    row_data[2],
                    row_data[3],
                    row_data[4],
                    row_data[5],
                    row_data[6],
                    row_data[1],
                )
            )
            yield (description, timeliner.TimeLinerType.CREATED, row_data[9])            
                    
    def run(self):
        """Runs the plugin and returns a TreeGrid"""
        show_corrupt_results = self.config.get("include-corrupt", None)
        malip = self.config.get('malIP', None)
        
        conn = sqlite3.connect('C:\\$home\\<USER_NAME>\\volatility3\\db_file.db')
        conn.isolation_level = None
        cursor = conn.cursor()
        # Create a TreeGrid with the specified column headers and types

        return renderers.TreeGrid(
            [
            ("Time\t\t",str),
             ("PID \t", str),
             ("Owner \t\t", str),
             ("Proto  ", str),
             ("LocalAddr", str),
             ("ForeignAddr\t", str),
             ("App \t\t", str),
             ("inboud/outbound\t", str),
             ("tags\t  ", str),
             ("representative\t\t", str),
             ("ids \t", str),
             ("abuse\t", str)
             ],
            self._generator(conn,cursor,malip,show_corrupt_results=show_corrupt_results),
        )