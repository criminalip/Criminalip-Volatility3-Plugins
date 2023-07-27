# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


__version__ = "1.0.0"

import re, requests,json,time,sys
from datetime import datetime, timedelta
import sqlite3
from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins import timeliner
from volatility3.framework.plugins.Criminalip.config import WhiteList,HardWhiteList 
from volatility3.framework.plugins.Criminalip.db_insert_modul import table_insert_url

API_KEY = '${CRIMINALIP_API_KEY}'

count =1
scanIdValue = 0
csv_file = "datatime"
current_time = datetime.now().strftime("%Y%m%d_%H%M%S")


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

    #They are functions using APIs related to Criminal IP domains. 

    def check_status(scanid):
        url = f"https://api.criminalip.io/v1/domain/lite/progress?scan_id={scanid}"
        headers = {
            "x-api-key": API_KEY
        }
    
        while True:
            response = requests.request("GET", url, headers=headers)
            result = json.loads(response.text)
            
            if result['data']['scan_percentage'] == -1 :
                return result['data']['scan_percentage']
            elif result['data']['scan_percentage'] == -2:
                return result['data']['scan_percentage']
            elif result['data']['scan_percentage'] == 100:
                return result['data']['scan_percentage']
            time.sleep(1)
        

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
                scanid = 'the scanid value does not exist'
                return scanid
                

    '''
    Check the domain report to see if there are any potentially threatening areas in the results. 
    
    # When Google or Criminal IP indicates that it is a phishing site:
    If result['data']['classification']['domain_type'] contains ['malware', 'adult', 'phishing'], or
    If result['data']['summary']['url_phishing_prob'] is 70.00 or higher, increment the variable "check" value by 3.

    # Since this is an indicator that has been comprehensively evaluated, the score is high:

    If result['data']['domain_score'] is '99% (Critical)' or '80% (Dangerous)', increment the variable "check" value by 3.

    # Recently created sites are more likely to be suspicious:

    If result['data']['main_domain_info']['domain_created'] is a site created within the last 3 years, increment the variable "check" value by 1.
    If any of the above conditions (probability of being a phishing site, conclusion of being a phishing site, or overall domain score) have a value, increment the variable "check" value by 2.

    # The displayed score of the IP associated with the domain is measured on an outbound basis, indicating a high risk:

    If the number of IPs in result['data']['summary']['abuse_record'] is 2 for moderate or 1 for critical or dangerous, increment the variable "check" value by 1.

    # If the 'dga_score' value is 8 or higher (a random string of characters), likely a phishing site, increment the variable "check" value by 1.
    # The domain has false domain URL information, so it is very likely a malicious site:

    If 'fake_https_url' is present, increment the variable "check" value by 1.

    # If any of the following is present, this is most likely a phishing site:

    If 'overlong_domain', 'punycode', or 'symbol_url' is present, increment the variable "check" value by 1.

    Finally, calculate the score for malicious information in the domain, labeling 0 as SAFE, 5 or less as MODERATE, 10 or less as DANGEROUS, and 15 or less as CRITICAL.
        
    
    '''    
    def check_domain(scanid):
        url =f"https://api.criminalip.io/v1/domain/lite/report/{scanid}"

        headers ={"x-api-key" : API_KEY}
        payload ={}

        response = requests.request("GET", url, headers=headers,data=payload)

        check_somthing =[]
        response = requests.request("GET", url, headers=headers)
        try:
            result = response.json()
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
            
            #data 
            if overlong_domain:
                check_somthing.append("overlong_domain")
            if punycode:
                check_somthing.append("punycode")
            if symbol_url:
                check_somthing.append("symbol_url")
            if check_somthing is not None:
                check_somthing = ','.join(check_somthing)
                
            abuse_total_record = abuse_record_dangerous + abuse_record_critical + abuse_record_moderate

            if domain_created == '':
                domain_created = '0000-00-00'
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
        except Exception as e:
            time.sleep(1)
            if result['status'] == 403:
                print("api limit exceeded")
                sys.exit(1)
            elif result['status'] == 500:
                print("server error")
                sys.exit(1)
            else:
                print(str(e))
                sys.exit(1)

    #This is a function with the ability to extract URLs from processes in memory and output a report on criminal IPs for all URLs except certificate-related URLs.
    def _generator(self, conn,cursor,procs, malDomain,hw):
        
        output_file = f"output_{current_time}.csv"
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
        with open(output_file, 'a') as file:
        # Write the header to the file
            header = "Level,CreateTime,PID,PName,URL,CriminalIpDomainScore,PhishingScoring,DomainType,DgaScore," \
                    "RealIP,DomainCreated,AbuseRecordTotal,FakeHttpsUrl,SuspiciousUrl\n"
            file.write(header)
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
                                
                                #Check for duplicate URLs and if a duplicate is found, display the existing data in the table. If it is not a duplicate, send an API request to retrieve the values
                                cursor.execute("SELECT * FROM urls WHERE url=?", (urlStr,))
                                duplicate_rows = cursor.fetchall()
                                
                                if duplicate_rows:

                                    for row in duplicate_rows:
                                        scanid_str = str(row[1])
                                        maldomain_scoring = row[2]
                                        domain_score = row[3]
                                        phishing_scoring = str(row[4])
                                        domain_type=row[5]
                                        dga_score=row[6]
                                        realip=row[7]
                                        domain_created=row[8]
                                        abuse_record_total= row[9]
                                        fake_https_url=row[10]
                                        suspicious_url=row[11]
                                else: 
                                    scanid = CIPCheckDomain.check_scanId(urlStr)
                                    scanid_str = str(scanid)
                                    if scanid == 'the scanid value does not exist':
                                        map = not_found
                                        table_insert_url(cursor,map,data,scanid)
                                        continue 
                                    status =CIPCheckDomain.check_status(scanid)
                                    if status == -1:
                                        scanid_str = "scan failed"                                    
                                        map = not_found
                                        
                                    elif status == -2:
                                        scanid_str = "Domain does not exist"
                                        map = not_found                       
                                            
                                    else:
                                        map = CIPCheckDomain.check_domain(scanid)
                                        scanid_str = str(scanid)
                                        domain_type = map["domain_type"]
                                        if isinstance(domain_type, list):
                                            domain_type_str = ", ".join(domain_type)
                                            map['domain_type'] = domain_type_str
                                        else:
                                            domain_type_str = str(domain_type)
                                            map['domain_type'] = domain_type_str

                                    # Get the values from the map using the helper function
                                    (
                                        domain_score,
                                        phishing_scoring,
                                        maldomain_scoring,
                                        domain_type,
                                        dga_score,
                                        realip,
                                        domain_created,
                                        abuse_record_total,
                                        fake_https_url,
                                        suspicious_url
                                    ) = CIPCheckDomain.get_values_from_map(map)
                                    table_insert_url(cursor,map,urlStr,scanid_str)


                                if (malDomain and (maldomain_scoring  == "critical" or  maldomain_scoring  == "dangerous")) or (not malDomain):
                                    data_str = f"0,{proc.get_create_time().replace(microsecond=0).strftime('%Y-%m-%d %H:%M:%S')},{str(proc.UniqueProcessId)}," \
                                            f"{proc_name},{urlStr},{domain_score},{phishing_scoring},{domain_type},{dga_score},{realip}," \
                                            f"{domain_created},{abuse_record_total},{fake_https_url},{suspicious_url}\n"
                                    file.write(data_str)
                                    yield (
                                        0,  # level
                                        (
                                            "{:<19}".format(proc.get_create_time().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")),
                                            "{:<10}".format(str(proc.UniqueProcessId)),  # pid
                                            "{:<7}".format(proc_name),  # pname
                                            "{:<20}".format(urlStr),  # url
                                            "{:<19}".format(domain_score), #criminal ip domain search score
                                            "{:<10}".format(str(phishing_scoring)),
                                            "{:<10}".format(str(domain_type)),
                                            "{:<10}".format(str(dga_score)),
                                            "{:<10}".format(str(realip)), #realip exit check
                                            "{:<10}".format(str(domain_created)), #domain created 
                                            "{:<10}".format(str(abuse_record_total)), # abuse record total number
                                            "{:<10}".format(str(fake_https_url)), #fake https url exit check
                                            "{:<10}".format(str(suspicious_url)) #suspicious url  exit check
                                        )
                                        )
                    
                    except MemoryError as e:
                        print(f"\nError occurred: {e}")
                        pass    
        conn.close() 
    
    def get_values_from_map(map):
        domain_score = map['domain_score']
        phishing_scoring = map['url_phishing_prob']
        maldomain_scoring = map['maldomain']
        domain_type = map['domain_type']
        dga_score = map['dga_score']
        realip = map['realip']
        domain_created = map['domain_created']
        abuse_record_total = map['abuse_record_total']
        fake_https_url = map['fake_https_url']
        suspicious_url = map['suspicious_url']
        
        return (
            domain_score,
            phishing_scoring,
            maldomain_scoring,
            domain_type,
            dga_score,
            realip,
            domain_created,
            abuse_record_total,
            fake_https_url,
            suspicious_url
        )
                            
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

        conn = sqlite3.connect('C:\\$home\\<USER_NAME>\\volatility3\\db_file.db')
        conn.isolation_level = None
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
                # ('CIP_ScanId  ', str),

            ],self._generator(conn,cursor,proc,malD,HW)
            
        )
        
        