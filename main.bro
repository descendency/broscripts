module MainDetect;

export {
    global time_threshold = 10min;

    global ip_whitelist: set[subnet] = {  };

    global port_list: set[port] = { };

    global server_list: set[addr] = { };

    global web_servers: set[addr] = { };
    global dns_servers: set[addr] = { };
    global file_servers: set[addr] = { };
    global email_servers: set[addr] = { };
    global dhcp_servers: set[addr] = { };
}
