@load ./main

module HTTPDetect;

export {
    redef enum Notice::Type += { Random_Subdomains,
        Website_Scanner };

    global bad_threshold: double = 10.0;
    global entropy_threshold: double = 3.5;
}

event bro_init()
{
    local r1 = SumStats::Reducer($stream="Suspicious Subdomain", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="Web Scanning", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name = "counting bad subdomains",
	    $epoch =  MainDetect::time_threshold,
	    $reducers = set(r1),
	    $threshold = HTTPDetect::bad_threshold,
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
	        NOTICE([$note=HTTPDetect::Random_Subdomains,
                $src = key$host,
    	 	    $msg = "Potential C2: Random looking Subdomains!",
                $n = |result["Suspicious Subdomain"]$unique_vals|,
        	    $sub = domains]);
	    }
    ]);

    SumStats::create([$name = "counting wrong URIs",
        $epoch = MainDetect::time_threshold,
        $reducers = set(r2),
        $threshold = HTTPDetect::bad_threshold,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
        {
            return result["Web Scanning"]$unique + 0.0;
        },
        $threshold_crossed() =
        {
            local URIs = "";
            local delimiter = ", ";
            for (p in result["Web Scanning"]$unique_vals)
                URIs += p$str + delimiter;

            URIs = sub_bytes(URIs, 0, |URIs| - |delimiter|);
            NOTICE([$note=HTTPDetect::Website_Scanner,
                $src = key$host,
                $msg = fmt("%s is scanning your website", key$host),
                $n = |result["Web Scanning"]$unique_vals|,
                $sub = URIs]);
        }
    ]);
}

event http_request(c: connection, method: string, original_URI:  string, unescaped_URI: string, version: string)
{
    if (!c?$http || c$id$resp_h !in MainDetect::local_subnets || c$id$resp_h in MainDetect::web_servers)
        return;

    SumStats::observe("Protocol Abuse",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($str=fmt("%s illegal HTTP request to %s", c$id$orig_h, c$id$resp_h)));

}

# Detect a high number of invalid website path requests from a given user.
# This might indicate a website path scanner or an idiot user.
event http_reply(c: connection, version: string, code: count, reason: string)
{
    # Skip if not valid HTTP or it is not an invalid request
    if (!c?$http && code >= 400)
        return;

    # Observing wrong attempts to connect from a 'user' (attacker perspective)
    SumStats::observe("Web Scanning",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($str=(c$http$host + c$http$uri)));

    # Observing wrong attempts to connect to the server (victim perspective)
    #SumStats::observe("???",
    #   SumStats::Key($host=c$id$resp_h),
    #   SumStats::Observation($str=(???)));
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
        if (to_addr(c$http$host) in MainDetect::ip_whitelist)
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
