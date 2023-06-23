# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


__author__  = "JisooLee"
__email__   = "jisoolee@aispera.com"
__version__ = "1.0.0"


from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.renderers import format_hints
from volatility3.plugins import timeliner
import re, requests,json,time,sys,sqlite3
from datetime import datetime, timedelta
from volatility3.framework.plugins.Criminalip.config import WhiteList,HardWhiteList 
from volatility3.framework.plugins.Criminalip.db_insert_modul import table_insert_ip

API_KEY = '${CRIMINALIP_API_KEY}'


count =1
scanIdValue = 0
csv_file = "datatime"

class CIPCheckDomain(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    _strings_regex = re.compile(b'[\x20-\x7E]+')
    _url_regex = re.compile(b'https?\:\/\/[a-zA-Z0-9\.\/\?\:@\-_=#]+\.[a-zA-Z]{2,6}[a-zA-Z0-9\.\&\/\?\:@\-_=#]*')
    _url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'




    @classmethod
    def get_requirements(self):
        return [
            requirements.TranslationLayerRequirement(
                name='primary',
                description='memory layer for kernel',
                architectures=['Intel32', 'Intel64']
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols',
                description='Windows kernel symbols'
            ),
            requirements.PluginRequirement(
                name='pslist',
                plugin=pslist.PsList,
                version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name='malD',
                description='Option to output only dangerous domains.',
                default=False,
                optional=True
            ),
            requirements.BooleanRequirement(
                name='HardWhite',
                description='Robust whiteless URL handling',
                default=False,
                optional=True
            )

        ]

    def check_status(scanid):
        url = f"https://api.criminalip.io/v1/domain/lite/progress?scan_id={scanid}"
        headers = {
            "x-api-key": API_KEY
        }
    
        while True:
            response = requests.request("GET", url, headers=headers)
            
            print(response)
            result = json.loads(response.text)
            print(result)
            if result['data']['scan_percentage'] == -1 :
                break

            elif result['data']['scan_percentage'] == -2:
                break
            elif result['data']['scan_percentage'] == 100:
                break

            time.sleep(5)
        
        return result['data']['scan_percentage']
    

    def check_scanId(url):
        headers = {"x-api-key": API_KEY}
        
        urls = f"https://api.criminalip.io/v1/domain/lite/scan?query={url}"
        response = requests.request("GET", urls, headers=headers)
        try:
            result = response.json()    
            scanid = result['data']['scan_id']
            return scanid
        except:
            if result['status'] == 403:
                print("api limit exceeded")
                sys.exit(1)
            elif result['status'] == 500:
                print("server error")
                sys.exit(1)
            else:
                scanid = '-'
                return scanid
                



        
    def check_domain(scanid):
        url =f"https://api.criminalip.io/v1/domain/lite/report/{scanid}"

        headers ={"x-api-key" : API_KEY}
        payload ={}

        response = requests.request("GET", url, headers=headers,data=payload)

        check_somthing =[]
        response = requests.request("GET", url, headers=headers)
        # print(response)
        try:
            result = response.json()
            # print(result)
            #json data
            domain_type =result['data']['classification']['domain_type']
            dga_score = result['data']['classification']['dga_score']
            url_phishing_prob = result['data']['summary']['url_phishing_prob'] 
            realip = result['data']['summary']['real_ip'] #int
                
            domain_score = result["data"]["domain_score"]
            
            domain_created = result['data']['main_domain_info']['domain_created']
            
            abuse_record_critical = result['data']['summary']['abuse_record']['critical']
            abuse_record_dangerous = result['data']['summary']['abuse_record']['dangerous']
            abuse_record_moderate = result['data']['summary']['abuse_record']['moderate']
            fake_https_url = result['data']['summary']['fake_https_url'] #bool
            
            overlong_domain = result['data']['summary']['overlong_domain']#bool
            punycode = result['data']['summary']['punycode']#bool
            symbol_url = result['data']['summary']['symbol_url'] #bool
            
            #data 가공
            if overlong_domain:
                check_somthing.append("overlong_domain")
            if punycode:
                check_somthing.append("punycode")
            if symbol_url:
                check_somthing.append("symbol_url")
            
            if check_somthing is not None:
                check_somthing = ','.join(check_somthing)
            
            abuse_total_record = abuse_record_dangerous + abuse_record_critical + abuse_record_moderate
            domain_created_int = int(domain_created.replace('-',''))
        
            current_time = datetime.now()
            three_years_ago = current_time - timedelta(days=365 * 3)
            
            three_years_ago_int = int(three_years_ago.strftime('%Y%m%d'))
            current_time_int = int(current_time.strftime('%Y%m%d'))
            
            
            #check maldomain
            check = 0
                
            phishing_domain_check = False
            high_domain_score = False
            if any(type in domain_type for type in ['malware', 'adult', 'phishing']) or url_phishing_prob >= 70.00:
                check += 3
                phishing_domain_check = True
            if domain_score in ['critical','dangerous']:
                check += 3
                high_domain_score  = True
            if dga_score >= 8.000:
                check += 1
            if domain_created_int >= three_years_ago_int and domain_created_int <= current_time_int: 
                if phishing_domain_check and high_domain_score:
                    check += 2
                check += 1
            if realip > 0:
                    check += 1
            if abuse_total_record >0 :
                if abuse_record_critical >0 or abuse_record_dangerous > 0 or abuse_record_moderate >=2:
                    check += 1
            if fake_https_url:
                check += 2
            if overlong_domain or punycode or symbol_url:
                check += 1
            
            #domain score check
            if check == 0:
                result1 =  'safe'
            elif check <= 2:
                result1 =  'moderate'
            elif check <= 8:
                result1 =  'dangerous'
            else:
                result1 = 'critical'
       
            # Return the required data bundled together in a single dictionary
            map ={
                "maldomain": result1,
                "domain_type":domain_type,
                "dga_score":  dga_score,
                "url_phishing_prob":  url_phishing_prob,
                "realip":  realip,
                "domain_score":  domain_score,
                "domain_created":  domain_created,
                "abuse_record_critical":  abuse_record_critical,
                "abuse_record_dangerous":  abuse_record_dangerous,
                "abuse_record_total":  abuse_total_record,
                "abuse_record_moderate": abuse_record_moderate,
                "fake_https_url": fake_https_url,
                "suspicious_url":check_somthing

            } 

            return map
       # Return the required data bundled together in a single dictionary  
        except:
            time.sleep(1)
            if result['status'] == 403:
                print("api limit exceeded")
                sys.exit(1)
            elif result['status'] == 500:
                print("server error")
                sys.exit(1)
            else:
                print("error")
                sys.exit(1)

    
    

    # #Creating a local DB and whether there are duplicate tables
    # def check_and_create_table(conn, cursor):
    #         cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
    #         table_exists = cursor.fetchone()
    
    # # If table doesn't exist, create it
    #         if not table_exists:
    #             cursor.execute('''CREATE TABLE urls (url TEXT,scanid TEXT, maldomain TEXT, domain_score TEXT, url_phishing_prob TEXT,domain_type TEXT,dga_score TEXT,realip TEXT,domain_created TEXT,abuse_record_total TEXT,fake_https_url TEXT,suspicious_url TEXT)''')
    
    
    # #data table insert
    # def table_insert(cursor,domain_result,data,scanid):

    #     cursor.execute('''INSERT INTO urls (
    #         url,
    #         scanid,
    #         maldomain,
    #         domain_score,
    #         url_phishing_prob,
    #         domain_type,
    #         dga_score,
    #         realip,
    #         domain_created,
    #         abuse_record_total,
    #         fake_https_url,
    #         suspicious_url

    #     ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
    #     (
    #             data,
    #             scanid,
    #             domain_result["maldomain"],
    #             domain_result["domain_score"],
    #             domain_result["url_phishing_prob"],
    #             domain_result["domain_type"],
    #             domain_result["dga_score"],
    #             domain_result["realip"],
    #             domain_result["domain_created"],
    #             domain_result["abuse_record_total"],
    #             domain_result["fake_https_url"],
    #             domain_result["suspicious_url"]
        
    #     )) 

        
       
           
    def _generator(self, conn,cursor,procs, malDomain,hw):
        
        not_found ={
        "domain_score": "N/A",
        "url_phishing_prob": "N/A",
        "maldomain": "N/A",
        "domain_type": "N/A",
        "dga_score": "N/A",
        "realip": "N/A",
        "domain_created": "N/A",
        "abuse_record_total": "N/A",
        "fake_https_url": "N/A",
        "suspicious_url": "N/A"
        }

        # CIPCheckDomain.check_and_create_table(conn, cursor)
        
        for proc in procs:
            proc_name = proc.ImageFileName.cast('string',max_length=proc.ImageFileName.vol.count,errors = 'replace')
            
            for vad in proc.get_vad_root().traverse():
                try:
                    proc_layer_name = proc.add_process_layer()
                    proc_layer = self.context.layers[proc_layer_name]

                    data_size = vad.get_end() - vad.get_start()
                   # Return the required data bundled together in a single dictionary
                    if data_size > 4295098360:
                        continue
                    data = proc_layer.read(vad.get_start(), data_size, pad=True)
                    
                    for string in self._strings_regex.findall(data):
                        for url in self._url_regex.findall(string):
                            should_skip = False
                            urlStr = url.decode()
                            
                            matches = re.findall(self._url_pattern , urlStr)
                            if len(matches) > 0:
                               # Return the required data bundled together in a single dictionary
                                urlStr = matches[0].rstrip('0123456789ABCDEFGHIHKLMNOPQRSTUVWXYZ~!@#$%^&*()_+`;:\'\\[]{},./?')
                            else:
                                pass

                            if hw:
                                for word in HardWhiteList:
                                    if word in urlStr:
                                        should_skip = True
                                        break
                            else:
                                if urlStr in WhiteList:
                                    should_skip = True
                           
    
                            if should_skip:
                                continue
                            print(urlStr)
                            #Check for duplicate URLs and if a duplicate is found, display the existing data in the table. If it is not a duplicate, send an API request to retrieve the values
                            cursor.execute("SELECT * FROM urls WHERE url=?", (urlStr,))
                            duplicate_rows = cursor.fetchall()
                            
                            if duplicate_rows:
                                for row in duplicate_rows:
                                    scanid_str = str(row[1])
                                    maldomain_scoring = row[2]
                                    total_domain_scoring = row[3]
                                    phishing_scoring = row[4]
                                    domain_type=row[5]
                                    dga_score=row[6]
                                    realip=row[7]
                                    domain_created=row[8]
                                    abuse_record_total= row[9]
                                    fake_https_url=row[10]
                                    suspicious_url=row[11]
                            else: 
                                scanid = CIPCheckDomain.check_scanId(urlStr)
                                print(scanid)
                                scanid_str = str(scanid)
                                if scanid == '-':
                                    map = not_found
                                    table_insert_ip(cursor,map,data,scanid)
                                    
                                    continue 
                                status =CIPCheckDomain.check_status(scanid)
                                if status == -1:
                                    scanid_str = "scan failed"                                    
                                    map = not_found
                                    self.set_fileder(map)
                                elif status == -2:
                                    scanid_str = "Domain does not exist"
                                    map = not_found
                                    self.set_fileder(map)       
                                else:
                                    # print(scanid)
                                    map = CIPCheckDomain.check_domain(scanid)
                                    self.set_fileder(map)
                                CIPCheckDomain.table_insert(cursor,map,urlStr,scanid)

                                time.sleep(3)
                            if (malDomain and (maldomain_scoring  == "critical" or  maldomain_scoring  == "dangerous")) or (not malDomain):
                                yield (
                                    0,  # level
                                    (
                                        "{:<19}".format(proc.get_create_time().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")),
                                        "{:<10}".format(str(proc.UniqueProcessId)),  # pid
                                        "{:<7}".format(proc_name),  # pname
                                        "{:<20}".format(urlStr),  # url
                                        "{:<19}".format(total_domain_scoring),
                                        "{:<10}".format(str(phishing_scoring)),
                                        "{:<10}".format(str(domain_type)),
                                        "{:<10}".format(str(dga_score)),
                                        "{:<10}".format(str(realip)),
                                        "{:<10}".format(str(domain_created)),
                                        "{:<10}".format(str(abuse_record_total)),
                                        "{:<10}".format(str(fake_https_url)),
                                        "{:<10}".format(str(suspicious_url)),
                                        "{:<10}".format(str(scanid_str)), # criminal ip Domain
                                    )
                                    )

                except MemoryError as e:
                    print(f"\nError occurred: {e}")
                    pass   
        conn.commit()  
        conn.close() 

    def set_fileder(self, map):
        total_domain_scoring=map['domain_score']
        phishing_scoring=map['url_phishing_prob']
        maldomain_scoring = map['maldomain']
        domain_type=map['domain_type']
        dga_score=map['dga_score']
        realip=map['realip']
        domain_created=map['domain_created']
        abuse_record_total= map['abuse_record_total']
        fake_https_url=map['fake_https_url']
        suspicious_url=map['suspicious_url']              
                                        
                            
    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Process: {row_data[0]} {row_data[2]} ({row_data[3]})"
            yield(description, timeliner.TimeLinerType.CREATED, row_data[8])
            
        
    def run(self):
        flt_function = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        proc = pslist.PsList.list_processes(
                    self.context,
                    self.config['primary'],
                    self.config['nt_symbols'],
                    filter_func = flt_function 
                )
        malD = self.config.get('malD',None)
        HW = self.config.get('HardWhite',None)
        conn = sqlite3.connect('C:\\Users\\<USER_NAME>\\volatility3\\db_file.db')
        cursor = conn.cursor()
        
        return renderers.TreeGrid(
            [
                ('Created \t', str),
                ('Pid ', str),
                ('Process \t', str),
                ('Url \t\t\t', str),
                ('TotalScore', str),
                ('PhishingScore', str),
                ('domain_type', str),
                ('dga_score', str),
                ('realip ', str),
                ('domain_created ', str),
                ('abuse_record_total ', str),
                ('fake_https_url ', str),
                ('suspicious_url', str),
                ('CIP_ScanId  ', str),

            ],self._generator(conn,cursor,proc,malD,HW)
            
        )
        
        