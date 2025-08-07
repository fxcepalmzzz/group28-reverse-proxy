Reverse Proxy Project Setup Instructions

1. Virtual Machine Setup
1.1. NGINX VM (192.168.100.10)

Internal Adapter Setup (eth0)
nmcli connection add type ethernet ifname eth0 con-name intnet-conn ip4 192.168.100.10/24
nmcli connection up intnet-conn

1.2. Backend HTTP Server 1 (192.168.100.20)
nmcli connection add type ethernet ifname eth0 con-name intnet-conn ip4 192.168.100.20/24
nmcli connection up intnet-conn

1.3. Backend HTTP Server 2 (192.168.100.30)
nmcli connection add type ethernet ifname eth0 con-name intnet-conn ip4 192.168.100.30/24
nmcli connection up intnet-conn


2. Web Server Installation

2.1. NGINX Reverse Proxy VM
sudo apt update
sudo apt install nginx -y
sudo systemctl start nginx
sudo systemctl enable nginx

2.2. Backend Apache Servers
sudo apt update
sudo apt install apache2 -y
sudo systemctl start apache2
sudo systemctl enable apache2

2.3. Test Connectivity from NGINX VM
curl http://192.168.100.20
curl http://192.168.100.30


3. Basic Load Balancing Configuration
Edit /etc/nginx/sites-available/default on the NGINX VM:
upstream backend_pool {
    server 192.168.100.20;
    server 192.168.100.30;
}

server {
    listen 80;

    location / {
        proxy_pass http://backend_pool;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

Restart NGINX:
sudo nginx -t
sudo systemctl reload nginx

Test with:
curl http://localhost


4. ModSecurity WAF with OWASP CRS (NGINX 1.26.3)

4.1. Dependencies
sudo apt update
sudo apt install -y git g++ build-essential autoconf automake libtool \
libxml2 libxml2-dev libyajl-dev pkg-config libcurl4-openssl-dev \
libgeoip-dev liblmdb-dev libpcre2-dev liblua5.3-dev libssl-dev \
zlib1g-dev libxslt1-dev libgd-dev libperl-dev

4.2. Compile and Install ModSecurity
cd /usr/local/src
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
git submodule init
git submodule update
./build.sh
./configure
make -j$(nproc)
sudo make install

4.3. Compile ModSecurity-nginx Module
cd /usr/local/src
git clone https://github.com/SpiderLabs/ModSecurity-nginx.git
wget http://nginx.org/download/nginx-1.26.3.tar.gz
tar -xvzf nginx-1.26.3.tar.gz
cd nginx-1.26.3

Get current build flags:
nginx -V 2>&1 | grep 'configure arguments'

Recompile with:
./configure <original-flags> --add-dynamic-module=/usr/local/src/ModSecurity-nginx
make modules

Copy module:
sudo mkdir -p /usr/lib/nginx/modules/
sudo cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

4.4. Configuration
sudo mkdir -p /etc/nginx/modsec
sudo cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sudo cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/

Edit /etc/nginx/modsec/modsecurity.conf:
SecRuleEngine On
SecAuditEngine On

Add OWASP CRS:
cd /etc/nginx/modsec
sudo git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
sudo cp crs-setup.conf.example crs-setup.conf

Append to modsecurity.conf:
Include /etc/nginx/modsec/coreruleset/crs-setup.conf
Include /etc/nginx/modsec/coreruleset/rules/*.conf

Enable module in /etc/nginx/nginx.conf:
load_module modules/ngx_http_modsecurity_module.so;

http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;
    ...
}

Restart:
sudo nginx -t
sudo systemctl reload nginx


5. Bot Protection and Rate Limiting

5.1. User-Agent Filtering
Edit /etc/nginx/nginx.conf in http block:
map $http_user_agent $bad_bot {
    default 0;
    ~*(?:evilbot|crawler|scrapy|badbot|masscan|wget|python-requests) 1;
}

In sites-available/default, inside server block:
if ($bad_bot) {
    return 403;
}


5.2. Rate Limiting
In /etc/nginx/nginx.conf:
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;

In sites-available/default, inside location block:
limit_req zone=one burst=20 nodelay;

Restart:
sudo nginx -t
sudo systemctl reload nginx


6. HTTPS with Windows Server Enterprise CA 

6.1. Windows Server 2022 Setup (Continued from 1. Virtual Machine Setup)
Set IP: 192.168.100.40
Hostname: MRPROXY-DC
Install: AD DS and DNS
Promote to Domain Controller (mrproxy.local)
Reboot
Install AD CS > Enterprise CA > Root CA > 2048-bit > 5 years

6.2. Certificate Template
Duplicate "Web Server" → NginxWebCert
Edit:
    Validity: 2 years
    Allow private key export
    Supply subject in request
    Grant Administrator enroll permission
Issue the template via certsrv.msc

6.3. Request + Export Certificate
Use MMC > Certificates > Local Computer
Request new cert: NginxWebCert
CN: MRProxy.test, SAN: DNS:MRProxy.test
Export as .pfx with private key

6.4. Move to NGINX
sudo mkdir -p /etc/nginx/ssl/
sudo cp MRProxy.test.pfx /etc/nginx/ssl/
cd /etc/nginx/ssl/
openssl pkcs12 -in MRProxy.test.pfx -nocerts -out MRProxy.test.key -nodes
openssl pkcs12 -in MRProxy.test.pfx -clcerts -nokeys -out MRProxy.test.crt
chmod 600 MRProxy.test.*

Edit sites-available/default:
server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name MRProxy.test;

    ssl_certificate /etc/nginx/ssl/MRProxy.test.crt;
    ssl_certificate_key /etc/nginx/ssl/MRProxy.test.key;

    location / {
        limit_req zone=one burst=20 nodelay;

        proxy_pass http://backend_pool;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

Restart NGINX:
sudo nginx -t
sudo systemctl reload nginx


7. Dashboard Deployment

7.1. Environment Setup
sudo apt update
sudo apt install python3-venv python3-pip -y
python3 -m venv dashboard-venv
source dashboard-venv/bin/activate
pip install streamlit pandas plotly streamlit-autorefresh psutil matplotlib

7.2. Directory Structure
mkdir ~/dashboard
cd ~/dashboard
# Add: dashboard.py, logparser.py, llm_assistant.py

7.3. Launching the Dashboard
cd ~/dashboard
source dashboard-venv/bin/activate
streamlit run dashboard.py


8. Attack Simulation

8.1. Slowloris (Kali)
git clone https://github.com/gkbrk/slowloris.git
cd slowloris
python3 slowloris.py MRProxy.test --https

8.2. R.U.D.Y.
cd /opt
sudo git clone https://github.com/darkweak/rudy
cd rudy
go build -o rudy rudy.go
sudo mv rudy /usr/local/bin/
rudy run -u https://MRProxy.test -c 5 -i 2s -p 500KB


