rule unknown_treat{

	meta:
		Author = "@Ahmad"
		Description = " This rule to Detect malicious bash script"
	strings:
		$bash = "#!/bin/bash"
		$rc = "/etc/rc.local"
		$url1 = "http://darkl0rd.com:7758/SSH-T"
		$url2 = "http://darkl0rd.com:7758/SSH-One"
		$ip_t = "iptables -f"
		$arg1 ="$hfs_s"
		$arg2 ="$hfs_m"
	condition:
		all of them


}
