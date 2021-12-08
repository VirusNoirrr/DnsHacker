# DnsHacker
Hello Guys This Tool is a Dnspoofer you can change the local dns to your own with this script 

How To Use The Script : 
    `python3 dnspoof.py` Will Apply default Configs (it will spoof all the websites, select all the targets connected on the network)
     ***Show help Menu*** : python3 dnspoof.py -h :
     

      usage: dnspoof.py [-h] [-d DOMAIN] [-i INTERFACE] [-t TARGET] [-r IP]
      optional arguments:
      -h, --help    show this help message and exit
      -d DOMAIN     Website or domain to spoof
      -i INTERFACE  Interface to listen on.
      -t TARGET     Target's IP. If not specified will add all.
      -r IP         IP to redirect the target to default is all.
