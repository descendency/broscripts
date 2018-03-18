# Note: None of the IPs listed in this script are my personal servers. It's just an example set
# to help you with your scripting ideas.

module TestModule;

export {
    redef enum Notice::Type += { Unauthorized_Server };
}

# Local subnets
global localips: set[subnet] = {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16,
};

# Server ports used inside of the local network
global serverports: set[port] = {
    25/tcp,
    80/tcp,
    443/tcp,
};

# Names of services running on local server ports
global servicenames: table[port] of string = {
    [20/tcp] = "FTP",
    [21/tcp] = "FTP",
    [22/tcp] = "SSH",
    [23/tcp] = "TELNET",
    [25/tcp] = "SMTP",
    [53/udp] = "DNS",
    [53/tcp] = "DNS",
    [67/udp] = "DHCP",
    [68/udp] = "DHCP",
    [69/udp] = "TFTP",
    [80/tcp] = "HTTP",
    [88/tcp] = "Kerberos",
    [110/tcp] = "POP3",
    [123/udp] = "NTP",
    [137/udp] = "NetBIOS",
    [138/udp] = "NetBIOS",
    [139/tcp] = "NetBIOS",
    [143/tcp] = "IMAP",
    [161/udp] = "SNMP",
    [162/udp] = "SNMP",
    [179/tcp] = "BGP",
    [389/tcp] = "LDAP",
    [389/udp] = "LDAP",
    [443/tcp] = "HTTPS",
    [445/tcp] = "SMB",
    [514/udp] = "SYSLOG",
};

# Servers serving email
global ftpservers: set[addr] = {

};

# Servers serving email
global mailservers: set[addr] = {
    192.168.1.2,
    192.168.1.3
};

# Servers serving web traffic
global webservers: set[addr] = {
    192.168.1.4,
    192.168.1.5,
    192.168.1.6,
};

# Map of all servers serving stuff over the local server ports inside of the localnet
global servers: table[port] of set[addr] = {
    [25/tcp] = mailservers,
    [80/tcp] = webservers,
    [443/tcp] = webservers,
};

# On any new connection, Check to see if an unauthorized machine is serving a well known service
event new_connection(c: connection)
{
    # If the responding host is local, is serving a well known service, and is not a designated server
    # raise a notice.
    if (c$id$resp_h in localips && c$id$resp_p in serverports && (c$id$resp_p !in servers || c$id$resp_h !in servers[c$id$resp_p]))
    {
        NOTICE([$note=TestModule::Unauthorized_Server,
                $msg = "Unauthorized " + servicenames[c$id$resp_p] + " server: " + addr_to_uri(c$id$resp_h),
                $n = 1,
                $conn = c,
                $uid = c$uid]);
    }

    # If the originating host is local, is serving a well known service, and is not a designated server
    # raise a notice.
    if (c$id$orig_h in localips && c$id$orig_p in serverports && (c$id$orig_p !in servers || c$id$orig_h !in servers[c$id$orig_p]))
    {
        NOTICE([$note=TestModule::Unauthorized_Server,
                $msg = "Unauthorized " + servicenames[c$id$orig_p] + " server: " + addr_to_uri(c$id$orig_h),
                $n = 1,
                $conn = c,
                $uid = c$uid]);
    }
}
