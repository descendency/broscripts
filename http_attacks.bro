module HTTPDetect;

export {
    global webserver_ips: set[addr] = { 199.7.51.190 };
    global ip_whitelist: set[subnet] = { 87.106.0.0/16 };
    redef enum Notice::Type += { Random_Subdomains };

    global time_threshold = 10min;
    global bad_subdomain_threshold: double = 10.0;
    global entropy_threshold: double = 2.0;
}

event bro_init()
{
    local r1 = SumStats::Reducer($stream="Suspicious Subdomain", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name = "counting bad subdomains",
	    $epoch =  HTTPDetect::time_threshold,
	    $reducers = set(r1),
	    $threshold = HTTPDetect::bad_subdomain_threshold,
	    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	    {
	        return result["Suspicious Subdomain"]$unique + 0.0;
	    },
	    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	    {
	        local domains = "";
            local cnt: count = 0;
	        for (p in result["Suspicious Subdomain"]$unique_vals)
	        {
                ++cnt;
	            domains += p$str + ", ";
	        }
	        domains = sub_bytes(domains, 0, |domains| - 2);
	        NOTICE([$note=HTTPDetect::Random_Subdomains,
                $src = key$host,
    	 	    $msg = "Potential C2: Random looking Subdomains!",
                $n = |result["Suspicious Subdomain"]$unique_vals|,
        	    $sub = domains]);
	    }
    ]);
}

# Detect high entropy subdomains.
# High randomness in one of the subdomains may be an indicator of a C2 channel.
event http_reply(c: connection, version: string, code: count, reason: string)
{
    # If the connection doesn't have an initialized HTTP::Info,
    # then skip this.
    if (!c?$http || (c?$http && !c$http?$host))
        return;


    # If it is an IP instead of a DNS name, then log it.
    # Unless it is an expected IP address.
    if (c$http$host == ip_addr_regex)
    {
        # Skip anything in the IP whitelist
        if (to_addr(c$http$host) in HTTPDetect::ip_whitelist)
            return;

        # Observe any host connecting to an IP.
        SumStats::observe("Suspicious Subdomain",
	        SumStats::Key($host=c$id$resp_h),
	        SumStats::Observation($str=c$http$host));
        return;
    }

    # Find the subdomain with the largest entropy.
    local maxentropy = 0.0;
    local subdomainarray = split_string(c$http$host, /\./);
    for (s in subdomainarray)
    {
        local entropyval: double = find_entropy(subdomainarray[s])$entropy;
        if (entropyval > maxentropy)
            maxentropy = entropyval;
    }

    # If the FQDN meets the entropy threshold, then count it.
    if (maxentropy >= HTTPDetect::entropy_threshold)
    {
        SumStats::observe("Suspicious Subdomain",
	        SumStats::Key($host=c$id$resp_h),
	        SumStats::Observation($str=c$http$host));
    }
}
