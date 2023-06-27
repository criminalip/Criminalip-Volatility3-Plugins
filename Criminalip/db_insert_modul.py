# ip data table insert
def table_insert_ip(cursor,ip_data,public_ip,verification):

    cursor.execute('''INSERT INTO ips (
        public_ip,
        port,
        app,
        inbound_outbound,
        tags,
        representative,
        ids,
        abuse,
        verification
        

    ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
    (
            public_ip,
            ip_data['port'],
            ip_data["app"],
            ip_data["inbound_outbound"],
            ip_data["tags"],
            ip_data["representative"],
            ip_data["ids"],
            ip_data["abuse"],
            verification
            
    
    )) 
    
# url data table insert

def table_insert_url(cursor,domain_result,data,scanid):

    cursor.execute('''INSERT INTO urls (
        url,
        scanid,
        maldomain,
        domain_score,
        url_phishing_prob,
        domain_type,
        dga_score,
        realip,
        domain_created,
        abuse_record_total,
        fake_https_url,
        suspicious_url

    ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
    (
            data,
            scanid,
            domain_result["maldomain"],
            domain_result["domain_score"],
            domain_result["url_phishing_prob"],
            domain_result["domain_type"],
            domain_result["dga_score"],
            domain_result["realip"],
            domain_result["domain_created"],
            domain_result["abuse_record_total"],
            domain_result["fake_https_url"],
            domain_result["suspicious_url"]
    
    )) 
