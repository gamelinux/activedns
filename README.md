<pre>
#
#   ____            __                     ____   __  __  _____
#  /    \          |  |   @               |    \ |  \ | ||  ___| (TM)
# |  /\  |.------..-----. _ -. .-.------. | |\  ||   \| ||___  |
# |  ==  ||  ----'`|  --'| |\ Y /| _--__|_| |/  ||      || \_| |
# |_/  \_||______| |____||_| \_/ |_______/|____/ |__|\__||_____|
#
#
</pre>

ActiveDNS
=========

An active domain name query tool to help keep track of domain name movements...

A tool to activly collect DNS records to aid Security Analysts tracking threats.

ActiveDNS activly resolves domain names and outputs the DNS-server answers
to a log file. ActiveDNS cache/aggregate the TTL responses for each domain
in memory and does not try to resolve the domains again before the TTL has
expired. This also limits the log file for unnecessary duplicates.

ActiveDNS can also save the state of when to resolve a domain again, so it will
request to a minimum even on a restart. It also supports reloading the list
of domains to query without having to restart ActiveDNS.

The logformat is compatible with the logformat of PassiveDNS.

Example output from the log file (/var/log/activedns.log):

#timestamp||dns-client ||dns-server||RR class||Query||Query Type||Answer||TTL||Count
1322849924.123456||192.168.0.1||8.8.8.8||IN||upload.youtube.com.||A||74.125.43.117||46587||1
1322849924.123456||192.168.0.1||8.8.8.8||IN||upload.youtube.com.||A||74.125.43.116||420509||1
1322849924.123456||192.168.0.1||8.8.8.8||IN||www.adobe.com.||CNAME||www.wip4.adobe.com.||43200||1
1322849924.123456||192.168.0.1||8.8.8.8||IN||www.adobe.com.||A||193.104.215.61||43200||1
1322849924.123456||192.168.0.1||8.8.8.8||IN||i1.ytimg.com.||CNAME||ytimg.l.google.com.||43200||1
1322849924.123456||192.168.0.1||8.8.8.8||IN||clients1.google.com.||A||173.194.32.3||43200||1

ActiveDNS uses Net::DNS::Async which makes it possible to query a lot of domains really fast.

** How can ActiveDNS be used: **

Typical usages:

1) Keep track of domain or IP history when working on incidents.
   Example:
   Your company has been hit with a repated email phising attack.
   The CC of the malware that is installed (if anyone falls for the
   attack) has been using domains: 
   bot1.mybots.info, bot2.mybots.info, newbot.mybots.info

   Keeping a track of the domains and what IP it resolves to, gives
   you an idea of what IPs the attacker might be in control of.

   Activly resolving the domains, reveals that for a small time period
   each monday, the attackers point the domains to a IP you have not
   seen before. Quering your NetFlow data, reveals that some of your
   machines acctually talked to that IP within the small periode it
   resolved to this IP. Digging further in your PassiveDNS logs, you find
   that the host talking to that IP, resolved the domain: badbot.hiddenbots.com

   Looking at PassiveDNS for the domain badbot.hiddenbots.com shows that
   this domains points to a new parking IP that you where not aware of, and you find
   from your PassiveDNS logs more domains pointing to that parking IP
   that seems to be related.

Questions, suggestions, sugar or flame is always welcome :)

I hope ActiveDNS gives you a new tool to fight malware and its herders...

(c)2013  -  Edward Bjarte Fjellskål

