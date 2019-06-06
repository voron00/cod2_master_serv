#!/usr/bin/perl

use strict;
use warnings;
use diagnostics;
use threads;
use IO::Socket;
use Digest::MD5;

my $master_port = 20710;
my $auth_port   = 20700;

my $msg;
my $maxlen = 1024;

# set default vars
my $debug         = 0;
my $guid_hash_key = '';    # Change this if you want guids

# set vars from env
if(defined $ENV{'DEBUG'}) {
	$debug = $ENV{'DEBUG'};
}
if(defined $ENV{'GUID_HASH_KEY'}) {
	$guid_hash_key = $ENV{'GUID_HASH_KEY'};
}


my %server_list;
my %auth_list;

&build_server_list;

my $master_socket = IO::Socket::INET->new(LocalPort => $master_port, Type => SOCK_DGRAM, Proto => 'udp', Timeout => 5) or die "Socket: $@";
my $auth_socket   = IO::Socket::INET->new(LocalPort => $auth_port,   Type => SOCK_DGRAM, Proto => 'udp', Timeout => 5) or die "Socket: $@";

my $auth_thread = async {&auth_server};
$auth_thread->detach();

my $info_thread = async {&update_servers_info};
$info_thread->detach();

&master_server;

sub update_servers_info {
	my $line;
	my $request_time = 120;
	my $timeout      = 1800;

	while (1) {
		foreach $line (keys %server_list) {
			my $time     = &get_time($server_list{$line});
			my $protocol = &get_protocol($server_list{$line});

			if ((time - $time) >= ($request_time)) {
				&request_server_info($line);
				sleep 1;
			}

			if ($protocol eq '0') {
				&request_server_info($line);
				sleep 1;
			}

			if ((time - $time) >= ($timeout)) {
				delete($server_list{$line});
			}
		}

		sleep 1;
	}
}

sub get_time {
	my $server = shift;

	if ($server =~ /^(\d+);(\d+)$/) {
		return $1;
	}

	return undef;
}

sub get_protocol {
	my $server = shift;

	if ($server =~ /^(\d+);(\d+)$/) {
		return $2;
	}

	return undef;
}

sub request_server_info {
	my $serverport = shift;
	my $message    = '';
	my $info       = "\xFF\xFF\xFF\xFFgetinfo";

	my $server;
	my $port;

	if ($serverport =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d{1,5})$/) {
		$server = $1;
		$port   = $2;
	}
	else {
		die("request_server_info: Invalid serverport $serverport");
	}

	my $d_ip = inet_aton($server);
	my $portaddr = sockaddr_in($port, $d_ip);

	send($master_socket, $info, 0, $portaddr) == length($info) or die("Cannot send message");
}

sub master_server {
	print "Starting master server on port $master_port\n";

	while (my $adr = recv($master_socket, $msg, $maxlen, 0)) {
		my ($port, $ipaddr) = sockaddr_in($adr);
		my $ip = inet_ntoa($ipaddr);

		if ($debug) {
			my $host = gethostbyaddr($ipaddr, AF_INET);

			unless (defined($host)) { $host = 'undefined'; }
			print "Master Server: client $ip:$port ($host) said $msg\n";
		}

		if ($msg =~ /^\xFF\xFF\xFF\xFFgetservers\s(\d+)\s?(\w+)?\s?(\w+)?$/) {
			&send_server_list($adr, $1);
		}
		elsif ($msg =~ /^\xFF\xFF\xFF\xFFheartbeat\sCOD-2$/) {
			&add_server("$ip:$port");
		}
		elsif ($msg =~ /^\xFF\xFF\xFF\xFFinfoResponse\s(.*)$/) {
			&update_server_info("$ip:$port", $1);
		}
		elsif ($msg =~ /^\xFF\xFF\xFF\xFFstatusResponse\s(.*)$/) {
			&update_server_info("$ip:$port", $1);
			&get_challenge($ip, $port);
		}
		elsif ($msg =~ /^\xFF\xFF\xFF\xFFheartbeat\sflatline$/) {
			&remove_server("$ip:$port");
		}
	}
}

sub auth_server {
	print "Starting authentication server on port $auth_port\n";

	while (my $adr = recv($auth_socket, $msg, $maxlen, 0)) {
		my ($port, $ipaddr) = sockaddr_in($adr);
		my $ip = inet_ntoa($ipaddr);

		if ($debug) {
			my $host = gethostbyaddr($ipaddr, AF_INET);

			unless (defined($host)) { $host = 'undefined'; }
			print "Authentication Server: client $ip:$port ($host) said $msg\n";
		}

		if ($msg =~ /^\xFF\xFF\xFF\xFFgetKeyAuthorize\s(\d)\s(\w+)(\sPB\s(\w+))?$/) {
			$auth_list{$ip} = $2;
		}
		elsif ($msg =~ /^\xFF\xFF\xFF\xFFgetIpAuthorize\s(-?\d+)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\w+)\s(\d)(\sPB\s(\w+))?$/) {
			my $guid   = 0;
			my $pbguid = 0;

			if (length($guid_hash_key) and defined($auth_list{$2})) {
				my $md5;

				$md5 = Digest::MD5->new;
				$md5->add($auth_list{$2}, $guid_hash_key);
				$guid = unpack('I', $md5->digest);

				if (length($guid) > 6) { $guid = substr($guid, -6); }

				$md5 = Digest::MD5->new;
				$md5->add($auth_list{$2}, $guid_hash_key);
				$pbguid = $md5->hexdigest;

				if ($debug) { print "Authorize: GUID: $guid PBGUID: $pbguid\n"; }
			}

			my $data = "\xFF\xFF\xFF\xFFipAuthorize $1 accept KEY_IS_GOOD $guid $pbguid";
			send($auth_socket, $data, 0, $adr) == length($data) or die("Socket error: $!");
		}
	}
}

sub build_server_list {
	my $line;
	my $list = "servers.txt";

	if (-e $list) {
		open(SERVER_LIST, $list) or die("unable to open $list: $!\n");

		while (defined($line = <SERVER_LIST>)) {
			$line =~ s/\s+$//;

			if ($line =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d{1,5})$/) {
				$server_list{$line} = time . ";0";
			}
		}
	}
}

sub add_server {
	my $server = shift;

	if (!defined($server_list{$server})) { $server_list{$server} = time . ";0"; }
	if ($debug) { print "Add: $server\n"; }
}

sub get_challenge {
	my $server = shift;
	my $port   = shift;

	my $random    = int(-1000000000 + rand(250000000));
	my $challenge = "\xFF\xFF\xFF\xFFgetchallenge $random";

	my $d_ip = inet_aton($server);
	my $portaddr = sockaddr_in($port, $d_ip);

	send($master_socket, $challenge, 0, $portaddr) == length($challenge) or die("Cannot send message");

	if ($debug) { print "Challenge: $server:$port $random\n"; }
}

sub update_server_info {
	my $server   = shift;
	my $msg      = shift;
	my $protocol = '0';

	if (defined($server_list{$server})) {
		if ($msg =~ /\\protocol\\(\d+)\\/) { $protocol = $1 }
		$server_list{$server} = time . ";" . $protocol;
	}

	if ($debug) { print "Update: $server Protocol: $protocol\n"; }
}

sub remove_server {
	my $server = shift;

	if (defined($server_list{$server})) { delete($server_list{$server}); }
	if ($debug) { print "Remove: $server\n"; }
}

sub send_server_list {
	my $adr       = shift;
	my $protocol  = shift;
	my $header    = "\xFF\xFF\xFF\xFFgetserversResponse\n\x00";
	my $delimiter = "\\";
	my $eot       = "EOT";
	my $eof       = "EOF";
	my $line;
	my $max_per_packet   = 20;
	my $per_packet_count = 0;
	my $data             = $header . $delimiter;
	my $server_protocol;

	foreach $line (keys %server_list) {
		$server_protocol = &get_protocol($server_list{$line});

		next if ($server_protocol ne $protocol);

		if ($line =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\:(\d{1,5})$/) {
			$data = $data . pack('C', $1);
			$data = $data . pack('C', $2);
			$data = $data . pack('C', $3);
			$data = $data . pack('C', $4);
			$data = $data . pack('n', $5);
			$data = $data . $delimiter;
			$per_packet_count++;

			if ($per_packet_count == $max_per_packet) {
				$data = $data . $eot;
				send($master_socket, $data, 0, $adr) == length($data) or die("Socket error: $!");

				$per_packet_count = 0;
				$data             = $header . $delimiter;
			}
		}
	}

	$data = $data . $eof;
	send($master_socket, $data, 0, $adr) == length($data) or die("Socket error: $!");
}
