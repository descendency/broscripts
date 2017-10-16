@load ./main

module DNSDetect;

export {
    redef enum Notice::Type += { Random_Subdomains };

    global bad_subdomain_threshold: double = 10.0;
    global entropy_threshold: double = 3.5;
}

event bro_init()
{
    local r1 = SumStats::Reducer($stream="Suspicious DNS Subdomain", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name = "counting bad DNS subdomains",
	    $epoch = MainDetect::time_threshold,
	    $reducers = set(r1),
	    $threshold = DNSDetect::bad_subdomain_threshold,
	    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	    {
	        return result["Suspicious Subdomain"]$unique + 0.0;
	    },
	    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	    {
	        local domains = "";
            local delimiter = ", ";
	        for (p in result["Suspicious Subdomain"]$unique_vals)
	            domains += p$str + delimiter;

	        domains = sub_bytes(domains, 0, |domains| - |delimiter|);
	        NOTICE([$note=DNSDetect::Random_Subdomains,
                $src = key$host,
    	 	    $msg = "Potential C2: Random looking Subdomains!",
                $n = |result["Suspicious DNS Subdomain"]$unique_vals|,
        	    $sub = domains]);
	    }
    ]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (!c?$dns)
        return;

    if (!c$dns$AA)
        return;

    local queryarray = split_string(c$dns$query, /\./);
    local maxentropy = 0.0;
    for (s in queryarray)
    {
        local entropyval: double = find_entropy(queryarray[s])$entropy;
        if (entropyval > maxentropy)
            maxentropy = entropyval;
    }

    if (maxentropy > DNSDetect::entropy_threshold)
        SumStats::observe("Suspicious DNS Subdomain",
            SumStats::Key($host=c$id$resp_h),
            SumStats::Observation($str=c$dns$query));
}
