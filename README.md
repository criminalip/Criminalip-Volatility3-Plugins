# **Introduction: Criminalip-Volatility3 Plugins**
​
- These plugins integrate Volatility with the Criminal IP CTI search engine, enabling users to execute Asset Search and Domain Search queries to identify potentially malicious IPs and domains.
- In the process of analyzing dump files, it is possible to identify the risk associated with IPs and domains contained within, enabling more advanced forms of memory forensics.
- The plugin is written based on Volatility 3 and may not be compatible with versions below Volatility 3.
- After downloading the file, you can place it in the volatility3/volatility3/foy/plugins directory to use it.
​
# **Prerequisites**
-   To access IP and domain data, you will need a Criminal IP API key. You can sign up for free at [https://www.criminalip.io/](https://www.criminalip.io/) and obtain your API key from the "My Information" section on the Criminal IP website.
## Project Setting
### Project file download
Download the following 3 files as zip files.
```c
Criminalip 
practice
db_file.db
```
First, the Ciminalip file is a file where the actual plugin exists, so put it in the 'volatility3volatility3frameworkplugins' location.
 You can look at the second part of the DB installation and overwrite the rest of the practice files and db_file.db.  
 Finally, you need to change the path where the api_key and db_file.db exist in each plugin.
​
​
### db install
Since there is a DB that stores a large amount of IP or URL, you can save credits because you do not query again in the part of the content that you have searched once. 
​
```c
$ pip install alembic   #installing for db migrations
```
Once the installation is complete, you can find by <Ctrl +p> and open the file 'alembic,ini'
In the 'alembic,ini' file, find the sqlalchemy.url part and change it as follows. 
Since we use sqlite3, we need to make the following changes. 
```c
sqlalchemy.url = sqlite:///db_file.db
```
After installation, move the practice and db_file.db files from the downloaded zip file into Volatility3.
​
### api_key & db file path setting
​
- aip key setting
​
Change the 'API_KEY' part of each plugin to The API_KEY issued from https://www.criminalip.io/mypage/information. 
```c
API_KEY = '${CRIMINALIP_API_KEY}'
```
​
- DB path setting
I have a volatility3 file in $home location and created it in the following format. However, you can set this part to the path where the user's volatility3 file exists. 
```c
conn = sqlite3.connect('C:\\$home\volatility3\\db_file.db')
```
​
### Download Cisco URL for Whitelisting
- Download the csv file containing 100,000 URLs from the Cisco Popularity List and add them to the WhiteList list in the Criminalip\config file according to the format.  
If you are unable to download the file from the above link, you can download the Cisco umbrella zip file from [https://github.com/PeterDaveHello/top-1m-domains].  
This zip file will be regularly uploaded so that you will be able to use it as new URLs are added.
​
​
# Project Components
## criminalipip plugin
### 1.criminalipip plugin explain
- The existing "netscan" plugin is one of the plugins that allow you to retrieve network connection information. The plugin code was modified and enhanced to integrate with Criminal IP.  
- You can judge whether the communicated IP is malicious using criminalip, and use the --malIP option to quickly extract only malicious IPs. 
- You can quickly check the activity status of the malicious IP by checking the communication time of the extracted malicious IP. 
​
### 2.criminalipip plugin rules
​
| Timeline | Pid | Owner  | proto |LocalAddr|ForeignAddr|inbound/outbound|tags|representative|ids|abuse
|--|--|--|--|--|--|--|--|--|--|--
| Connection time information |Pid value  |Process name|Protocol type|Src IP and port information|Dst IP and  port information|Score of the dst IP in Criminal IP|Information regarding issues associated with the dst IP | Representative domain information of the IP |Information corresponding to snort rules|Reported incidents and the number of malicious codes associated with the IP

### 3.Commands available in the criminalip plugin
```c
$ Criminalip.criminalipip
$ Cariminalip.criminalipip --malIP
```
​
### 4.Project launch screen
​
| criminalipip | criminalipip --malIP 
|--|--
|![cipip](https://github.com/criminalip/Criminalip-Volatility3-Plugins/assets/114474963/f2111df5-44a1-4663-a6bf-4c2170cae28b)|![cipip_malIP](https://github.com/criminalip/Criminalip-Volatility3-Plugins/assets/114474963/989fc6e9-37b3-4a41-b19b-5668dc030e3d)





## criminalipdomain plugin
### 1.criminalipdomain plugin explain
- It is a plugin that returns only URLs where malicious activity exists, as a result value verified by criminalip.
- By checking a series of results in a list, we expect to be able to catch the process of redirecting malicious URLs.
​
### 2.criminalipdomain plugin rules
​
| Timeline | Pid | Process  | URL |TotalScore|Phishing Score|Domain type|DGA score|Real IP|Domain created|abuse|Fake https URL| Suspicious URL
|--|--|--|--|--|--|--|--|--|--|--|--|--
| Connection time information |Pid value  |Process name|URL information extracted from the process|Final score while searching for URL in Domain Search |The probability of the URL being a phishing|Domain category information set by Google  |Score for AI determination of whether a domain was created with a random naming convention  |Number of real IPs |Domain creation date |Number of IPs connected to  your domain that have been reported as malicious |False https URL status|URLs that may be suspected of phishing: longer than 30 characters in length / use punycode / presence of the @ string​

### 3.Commands available in the criminalipdomain plugin
```c
$ Criminalip.criminalipdomain
$ Criminalip.criminalipdomain --malD
$ Criminalip.criminalipdomain --HardWhite
$ Criminalip.criminalipdomain --malD --HardWhite
```
### 4.Project launch screen
| criminalipdomian | criminalipdomain --malIP | criminalipdomain --malIP --HardWhite
|--|--|--
|![cipdomain](https://github.com/criminalip/Criminalip-Volatility3-Plugins/assets/114474963/58b59d91-2da1-4600-8947-d88284e9b1f2)|![cipdomian_malD](https://github.com/criminalip/Criminalip-Volatility3-Plugins/assets/114474963/072e837e-20f7-4839-a89e-e9beca28bfb1)|![cipdomain_malD_hw](https://github.com/criminalip/Criminalip-Volatility3-Plugins/assets/114474963/c1c9059c-dca1-436a-ad42-3520f0c1f19a).


# **License**
​
Volatility Software License  
Version 1.0 dated October 3, 2019.  
This license covers the Volatility software, Copyright 2019 Volatility Foundation.  
Software  
[https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt)
