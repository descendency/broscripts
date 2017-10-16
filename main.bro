module MainDetect;

export {
    global time_threshold = 10min;

    global ip_whitelist: set[subnet] = {  };

    global web_servers: set[addr] = { };
    global dns_servers: set[addr] = { };
    global file_servers: set[addr] = { };
    global email_servers: set[addr] = { };
    global dhcp_servers: set[addr] = { };
}
