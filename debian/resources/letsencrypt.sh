#!/bin/sh

# FusionPBX - Install
# Mark J Crane <markjcrane@fusionpbx.com>
# Copyright (C) 2018
# All Rights Reserved.

#move to script directory so all relative paths work
cd "$(dirname "$0")"

#includes
. ./config.sh

if [ .$switch_tls = ."true" ]; then

	#make sure the freeswitch directory exists
	mkdir -p /etc/freeswitch/tls

	#make sure the freeswitch certificate directory is empty
	rm /etc/freeswitch/tls/*
fi


#request the domain name, email address and wild card domain
read -p 'Domain Name: ' domain_name
read -p 'Email Address: ' email_address

#wildcard detection
wildcard_domain=$(echo $domain_name | cut -c1-1)
if [ "$wildcard_domain" = "*" ]; then
	wildcard_domain="true"
else
	wildcard_domain="false"
fi

# Get and install acme.sh
wget -O -  https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s -- --install-online -m  $email_address

if [ .$acme_challenge_type = ."dns-01" ]; then
	letsencrypt_env_file=./letsencrypt/letsencrypt-env.sh

	if [ ! -f $letsencrypt_env_file ]; then
		error "letsencrypt env file $letsencrypt_env_file not found."
		exit 1
	fi

	# Source env file containing dns-01 challenge secrets
	. $letsencrypt_env_file

	~/.acme.sh/acme.sh --issue --install-cert --dns dns_$acme_dns_provider -d $domain_name \
		--key-file       /etc/ssl/private/nginx.key \
		--fullchain-file /etc/ssl/certs/nginx.crt \
		--reloadcmd     "/usr/sbin/nginx -s reload"

	if [ .$switch_tls = ."true" ]; then
		~/.acme.sh/acme.sh --issue --install-cert --dns dns_$acme_dns_provider -d $domain_name \
			--key-file       /etc/freeswitch/tls/privkey.pem \
			--cert-file		 /etc/freeswitch/tls/cert.pem \
			--fullchain-file /etc/freeswitch/tls/fullchain.pem \
			--ca-file		 /etc/freeswitch/tls/chain.pem \
			--reloadcmd     "cat /etc/freeswitch/tls/fullchain.pem > /etc/freeswitch/tls/all.pem && cat /etc/freeswitch/tls/privkey.pem >> /etc/freeswitch/tls/all.pem"
	fi
elif [ .$wildcard_domain = ."true" && .$acme_challenge_type = ."http-01" ]; then
	verbose "Wildcard domain ist not supported by http-01 challenge, using manual dns challenge"

	~/.acme.sh/acme.sh  --issue --install-cert --dns -d $domain_name \
		--key-file       /etc/ssl/private/nginx.key \
		--fullchain-file /etc/ssl/certs/nginx.crt \
		--reloadcmd     "/usr/sbin/nginx -s reload"

	~/.acme.sh/acme.sh --renew -d $domain_name

	if [ .$switch_tls = ."true" ]; then
		~/.acme.sh/acme.sh  --issue --install-cert --dns -d $domain_name \
			--key-file       /etc/freeswitch/tls/privkey.pem \
			--cert-file		 /etc/freeswitch/tls/cert.pem \
			--fullchain-file /etc/freeswitch/tls/fullchain.pem \
			--ca-file		 /etc/freeswitch/tls/chain.pem \
			--reloadcmd     "cat /etc/freeswitch/tls/fullchain.pem > /etc/freeswitch/tls/all.pem && cat /etc/freeswitch/tls/privkey.pem >> /etc/freeswitch/tls/all.pem"
	fi

elif [ .$acme_challenge_type = ."http-01" ]; then
	~/.acme.sh/acme.sh --install-cert --nginx -d $domain_name \
		--key-file       /etc/ssl/private/nginx.key \
		--fullchain-file /etc/ssl/certs/nginx.crt \
		--reloadcmd     "/usr/sbin/nginx -s reload"

	if [ .$switch_tls = ."true" ]; then
		~/.acme.sh/acme.sh  --install-cert --nginx -d $domain_name \
			--key-file       /etc/freeswitch/tls/privkey.pem \
			--cert-file		 /etc/freeswitch/tls/cert.pem \
			--fullchain-file /etc/freeswitch/tls/fullchain.pem \
			--ca-file		 /etc/freeswitch/tls/chain.pem \
			--reloadcmd     "cat /etc/freeswitch/tls/fullchain.pem > /etc/freeswitch/tls/all.pem && cat /etc/freeswitch/tls/privkey.pem >> /etc/freeswitch/tls/all.pem"
	fi

else
	error "Unsupported acme challenge type $acme_challenge_type. Only dns-01 and http-01 are supported"
	exit 1
fi


#remove the wildcard and period
if [ .$wildcard_domain = ."true" ]; then
      domain_name=$(echo "$domain_name" | cut -c3-255)
fi


# #set the domain alias
# domain_alias=$(echo "$domain_name" | head -n1 | cut -d " " -f1)

# #create an alias when using wildcard dns
# if [ .$wildcard_domain = ."true" ]; then
# 	echo "*.$domain_name > $domain_name" > /etc/dehydrated/domains.txt
# fi

# #add the domain name to domains.txt
# if [ .$wildcard_domain = ."false" ]; then
# 	echo "$domain_name" > /etc/dehydrated/domains.txt
# fi

# #request the certificates
# if [ .$wildcard_domain = ."true" ]; then
# 	./dehydrated --cron --domain *.$domain_name --preferred-chain "ISRG Root X1" --algo rsa --alias $domain_alias --config /etc/dehydrated/config --out /etc/dehydrated/certs --challenge dns-01 --hook /etc/dehydrated/hook.sh
# fi
# if [ .$wildcard_domain = ."false" ]; then
# 	./dehydrated --cron --alias $domain_alias --preferred-chain "ISRG Root X1" --algo rsa --config /etc/dehydrated/config --out /etc/dehydrated/certs --challenge http-01
# fi


#setup freeswitch tls
if [ .$switch_tls = ."true" ]; then

	#add symbolic links
	ln -s /etc/freeswitch/tls/all.pem /etc/freeswitch/tls/agent.pem
	ln -s /etc/freeswitch/tls/all.pem /etc/freeswitch/tls/tls.pem
	ln -s /etc/freeswitch/tls/all.pem /etc/freeswitch/tls/wss.pem
	ln -s /etc/freeswitch/tls/all.pem /etc/freeswitch/tls/dtls-srtp.pem

	#set the permissions
	chown -R www-data:www-data /etc/freeswitch/tls

fi  
