$ORIGIN exxampled.com.
$TTL 86400
@	IN	SOA	dns1.exxampled.com.	hostmaster.exxampled.com. (
			2001062501 ; serial
			21600      ; refresh after 6 hours
			3600       ; retry after 1 hour
			604800     ; expire after 1 week
			86400 )    ; minimum TTL of 1 day


	IN	NS	ns1.exxampled.com.

	IN	MX	10	mx.exxampled.com.

ns1	IN	A	127.0.0.1
mx IN	A	127.0.0.1
