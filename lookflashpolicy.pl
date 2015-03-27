#!/usr/bin/perl -w
#!/usr/local/bin/perl -w

# -------------------------------------------------------------------------
# Xtreme Flash Policy [NandOX+Endurance] 
# $Id: lookflashpolicy.pl,v 1.1 2012/11/01 00:10:17 nando Exp $
#
# Copyright (C) 2015 by NandOX IRC Chat Network <info@nandox.com>
# http://www.nandox.com/
#
# This file is part of Xtreme Flash Policy [NandOX+Endurance].
#
# Xtreme Flash Policy [NandOX+Endurance] is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Xtreme Flash Policy [NandOX+Endurance] is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Xtreme Flash Policy [NandOX+Endurance]; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# or see <http://www.gnu.org/licenses/gpl-2.0.txt>.
# ---------------------------------------------------------------------------------
#
# Coded by Hernando Furlan
#
#          mailto: <base64('ZGV2bmFuZG9AZ21haWwuY29t')>
#                  Public GnuPG/PGP key available at: http://www.ifork.com.ar/keyring/hfurlan.asc
#                  Key fingerprint: 5FA3 B1B9 AAF8 F3F2 54A9  471A F6AA 2DEB AD63 2E21
#
#          mailto: <base64('aGZ1cmxhbkBpZm9yay5jb20uYXI=')>
#                  Public GnuPG/PGP key available at: http://about.nandox.com/nando.asc
#                  Key fingerprint: 80C0 6865 749E 26BD 31C6  2993 0D3A FC81 6DF9 092E
#
#         website:
#                  http://www.nandox.com
#                  http://www.nandox.com.ar
#
# -------------------------------------------------------------------------
# See README.txt for installation instructions and changelog details
# -------------------------------------------------------------------------

# -------------------------------
# No changes needed in this file!
# -------------------------------

require 5.6.0;
use threads;
use Thread::Queue;
use Sys::Hostname;
use Data::Dumper;
use Socket;
use POSIX;
use strict;
use warnings;
no warnings 'threads';
use constant DEBUG   => 0; # Enable debug (prevent to background main process) only for development purposes, disable on production environments
use constant VERSION => 1.1;

our %conf;
if (-e "config.pm") {
    eval "use config qw( %conf );";
} else { 
    die("Xtreme Flash Policy: Please set your configuration at 'config.pm-dist' and rename it to 'config.pm' before to run.\n");
}

=head1 NAME

Xtreme Flash Policy [NandOX+Endurance] - http://www.nandox.com/

=head1 SYNOPSIS

Usage: ./lookflashpolicy.pl <start|stop> [force]

=head1 DESCRIPTION

Threaded Flash Policy Agent Daemon with IRC related features

See README.txt for installation instructions and changelog details

=head1 AUTHOR

 Coded by Hernando Furlan

          mailto: <base64('ZGV2bmFuZG9AZ21haWwuY29t')>
                  Public GnuPG/PGP key available at: http://www.ifork.com.ar/keyring/hfurlan.asc
                  Key fingerprint: 5FA3 B1B9 AAF8 F3F2 54A9  471A F6AA 2DEB AD63 2E21

          mailto: <base64('aGZ1cmxhbkBpZm9yay5jb20uYXI=')>
                  Public GnuPG/PGP key available at: http://about.nandox.com/nando.asc
                  Key fingerprint: 80C0 6865 749E 26BD 31C6  2993 0D3A FC81 6DF9 092E

         website:
                  http://www.nandox.com
                  http://www.nandox.com.ar

=cut

# -------------------------------------------------------------------------
# bool &set_pid(int pid)
#
# Store main pid
# -------------------------------------------------------------------------
sub set_pid {
    my ($pid) = @_;

    open(OUT, ">".$conf{'LOOK_PIDFILE'});
    print OUT $pid;
    close(OUT);

    return(1);
}

# -------------------------------------------------------------------------
# int pid &get_pid(void);
#
# Return return current main pid
# -------------------------------------------------------------------------
sub get_pid {
    my (@argv) = @_;

    my $pid = 0;
    if(-e $conf{'LOOK_PIDFILE'}) {
        open(IN, "<".$conf{'LOOK_PIDFILE'});
        $pid = do { local $/; <IN> };
        close(IN);
    }
    return($pid);
}

# -------------------------------------------------------------------------
# bool &rem_pid(void)
#
# Removes main pid
# -------------------------------------------------------------------------
sub rem_pid {
    my (@argv) = @_;

    unlink $conf{'LOOK_PIDFILE'};

    return(1);
}

# -------------------------------------------------------------------------
# bool &looksharp_start(void)
#
# Start main process
# -------------------------------------------------------------------------
sub looksharp_start {
    my (@argv) = @_;

    # Start without fork if debug enabled
    if(DEBUG) {
        print "Running in DEBUG MODE\n";
        print "Background process disabled and usefull info will be output to console\n";
        print "(Hit Ctrl-C to stop process)\n\n";

        &looksharp_main();

    } else {
        &looksharp_fork();
    }

    return(1);
}

# -------------------------------------------------------------------------
# bool &looksharp_stop(void)
#
# Stop main process
# -------------------------------------------------------------------------
sub looksharp_stop {
    my (@argv) = @_;

    &looksharp_unfork();

    return(1);
}

# -------------------------------------------------------------------------
# bool &looksharp_fork(void)
#
# Start main process as background daemon
# -------------------------------------------------------------------------
sub looksharp_fork {
    my (@argv) = @_;

    if((!&get_pid()) || (($ARGV[1]) && ($ARGV[1] eq 'force'))) {
        $SIG{CHLD} = 'IGNORE';
        my $pid = fork();

        if(!$pid) {
            &looksharp_main(); # This is an infinite loop

        } else {
            print "  +++ [PID:".$pid."] Starting Xtreme Flash Policy...\n";

            if(!&set_pid($pid)) {
                print "  +++ WARNING: Unable to save pid!\n";
            }
        }

    } else {
        print "  +++ ERROR: It seems there is a process running. Add [force] parameter if you believe it is incorrect.\n";
    }

    return(1);
}

# -------------------------------------------------------------------------
# bool &looksharp_unfork(void)
#
# Kill our daemon
# -------------------------------------------------------------------------
sub looksharp_unfork {
    my (@argv) = @_;

    my $pid = &get_pid();

    if($pid) {
        # Give 5 seconds of time to flush
        print "  +++ [PID:".$pid."] Stopping Xtreme Flash Policy...\n";
        kill('TERM', $pid);
        &rem_pid();

    } else {
        print "  +++ ERROR: It seems there is NO process running. If you believe it is incorrect kill 'by hand'.\n";

    }

    return(1);
}

# -------------------------------------------------------------------------
# bool &looksharp_main(void);
#
# Start main process
# -------------------------------------------------------------------------
sub looksharp_main {
    my (@argv) = @_;

    my %peerpoolmethods = (0 => "QUEUE", 1 => "FORK", 2 => "THREAD");

    # Prepare Flash Policy Server socket
    my $policy_proto = getprotobyname('tcp');
    socket(PolicySock, PF_INET, SOCK_STREAM, $policy_proto) 
        || die "Can't open socket $!\n";
    setsockopt(PolicySock, SOL_SOCKET, SO_REUSEADDR, 1)
        || die "Can't set socket option to SO_REUSEADDR $!\n";
    my $policy_packet_ip = inet_aton($conf{'POLICY_BINDADDR'});
    my $policy_sin = sockaddr_in($conf{'POLICY_PORT'}, $policy_packet_ip);
    my $policy_sin_fallback = sockaddr_in($conf{'POLICY_PORT_FALLBACK'}, $policy_packet_ip);

    if(bind(PolicySock, $policy_sin)) {
        print "Xtreme Flash Policy cross-domain server bind successfull. [".$conf{'POLICY_BINDADDR'}.":".$conf{'POLICY_PORT'}."]\n" if DEBUG;
    } elsif (bind(PolicySock, $policy_sin_fallback)) {
        print "Xtreme Flash Policy cross-domain server bind successfull. [".$conf{'POLICY_BINDADDR'}.":".$conf{'POLICY_PORT_FALLBACK'}."] (Fallback port)\n" if DEBUG;
    } else {
        die "Can't bind to main nor fallback port: $! \n";
    }

    listen(PolicySock, $conf{'POLICY_CONNQUEUE'})
        || die "Listen socket: $!";

    print "Listening for incoming cross-domain requests using ".$peerpoolmethods{$conf{'POLICY_PEERPOOLMETHOD'}}." pool method.\n" if DEBUG;
    print "Connection flood protection is: ".($conf{'FLOODPRO_ENABLE'}?"Enabled":"Disabled")."\n" if DEBUG;

    # Queue to hook IRC channel messages
    my $IRCQueue = Thread::Queue->new;

    # Up our IRC Bot if enabled
    if($conf{'IRC_ENABLE'}) {
        my $thr_IRC = threads->create("th_IRCConnManager", $IRCQueue);
        my $tid_IRC = $thr_IRC->tid();
        print "IRC Bot is enabled. Manager launched on thread tid(".$tid_IRC.")\n" if DEBUG;
        $thr_IRC->detach();
    }

    # Queue to hook Log file messages
    my $LogQueue = Thread::Queue->new;

    # Up our log server if everything ok and enabled
    if($conf{'POLICY_LOG'}) {
        my $thr_LogQueue = threads->create("th_LogQueue", $LogQueue);
        my $tid_LogQueue = $thr_LogQueue->tid();
        print "Log to file is enabled. Queue UP on tid(".$tid_LogQueue.")\n" if DEBUG;
        $thr_LogQueue->detach();
    }

    # Accept connections to our policy server infinite loop
    my $cid; # Connection ID assigned

    while(my $packet_addr = accept(PolicyStream, PolicySock)) {
        my ($peer_port, $peer_ip) = sockaddr_in($packet_addr);
        my $peer_ip_str = inet_ntoa($peer_ip);

        if($conf{'FLOODPRO_ENABLE'}) {
            unless (&look_floodconn_verify($peer_ip_str, $IRCQueue, $LogQueue)) {
                close PolicyStream;
                next;
            }
        }

        $cid++;

        print "Connection accepted from: [".$peer_ip_str.":".$peer_port."]\n" if DEBUG;

        # Queue
        if($conf{'POLICY_PEERPOOLMETHOD'} == 0) {
            print "Queued connection as cid(".$cid.")\n" if DEBUG;
            &th_PolicyStreamReadData(\*PolicyStream, $peer_ip_str, $peer_port, $cid, $IRCQueue, $LogQueue);

        # Fork
        } elsif($conf{'POLICY_PEERPOOLMETHOD'} == 1) {
            $SIG{CHLD} = 'IGNORE';
            pipe(READER, WRITER);

            my $pid = fork();

            if(!$pid) {
                close READER;
                my $statusmsg = &th_PolicyStreamReadData(\*PolicyStream, $peer_ip_str, $peer_port, $cid, $IRCQueue, $LogQueue);
                print WRITER $statusmsg;

                exit(1);

            } else {
                print "Forked connection as pid(".$pid.")\n" if DEBUG;
                close WRITER;

                my $statusmsg = <READER>;                
                $IRCQueue->enqueue($statusmsg) if $conf{'IRC_LOG'};
                $LogQueue->enqueue($statusmsg) if $conf{'POLICY_LOG'};
            }

        # Thread
        } else { 
            my $thr_Policy = threads->create("th_PolicyStreamReadData", \*PolicyStream, $peer_ip_str, $cid, $peer_port, $IRCQueue, $LogQueue);
            my $tid_Policy = $thr_Policy->tid();
            print "Threaded connection as tid(".$tid_Policy.")\n" if DEBUG;
            $thr_Policy->detach();
        }


        close PolicyStream;
    }

    return(1);
}

# -------------------------------------------------------------------------
# string status &th_PolicyStreamReadData(handler sock_stream)
#
# Read request from new connection as separated thread to improve security
# -------------------------------------------------------------------------
sub th_PolicyStreamReadData {
    our ($PolicyStream, $peer_ip_str, $peer_port, $cid, $IRCQueue, $LogQueue) = @_;
    my $thr = threads->self();
    my $tid = $thr->tid();

    # Initialize bitmask and mark socket in $rin
    my $rin = '';
    vec($rin, fileno($PolicyStream), 1) = 1;
    my $nfound = select(my $rout = $rin, undef, undef, $conf{'POLICY_CONNTIMEOUT'});

    # Useful id info
    my $id_info;

    # Queue
    if($conf{'POLICY_PEERPOOLMETHOD'} == 0) {
        $id_info = "cid(".$cid.")";

    # Fork
    } elsif($conf{'POLICY_PEERPOOLMETHOD'} == 1) {
        $id_info = "pid(".$$.")";

    # Thread
    } else {
        $id_info = "tid(".$tid.")";

    }

    # What to log
    my $log_connsource = "Connection from [".$peer_ip_str.":".$peer_port."] - ";
    my $log_connstatus;
    my $log_connid = " - ".$id_info;

    if (vec($rout, fileno($PolicyStream), 1)){
        print $id_info." - Request received. Let's me verify this...\n" if DEBUG;

        my $buffer;
        sysread($PolicyStream, $buffer, 32);

        if($buffer =~ /^\<policy\-file\-request\/\>.*$/) {
            print $id_info." - Valid request, sending policy to client...\n" if DEBUG;
            print $PolicyStream "<?xml version=\"1.0\"?>\n"
                               ."<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\n"
                               ."<cross-domain-policy>\n"
                               ."   <site-control permitted-cross-domain-policies=\"master-only\"/>\n"
                               ."   <allow-access-from domain=\"".$conf{'POLICY_ALLOW_HOST'}."\" to-ports=\"".$conf{'POLICY_ALLOW_PORT'}."\" />\n"
                               ."</cross-domain-policy>\n"
                               ."<!-- Xtreme Flash Policy [NandOX.com] -->\n";

            $log_connstatus = "Valid request, policy sent";

        } else {
            print $id_info." - Invalid request. Ignoring.\n" if DEBUG; 
            $log_connstatus = "Invalid request. Ignoring";
        }

    } else {
        print $id_info." - Waiting request timeout.\n" if DEBUG;
        $log_connstatus = "Waiting request timeout";
    }

    print $id_info." - Closing client link and terminating transaction.\n" if DEBUG;

    if($conf{'POLICY_PEERPOOLMETHOD'} != 1) { # Method FORK (1) do it using pipe instead
        $IRCQueue->enqueue($log_connsource.$log_connstatus.$log_connid) if $conf{'IRC_LOG'};
        $LogQueue->enqueue($log_connsource.$log_connstatus.$log_connid) if $conf{'POLICY_LOG'};
    }

    return($log_connsource.$log_connstatus.$log_connid);
}

# -------------------------------------------------------------------------
# int &th_IRCConnManager(handler queue)
#
# Launch IRC Bot
# -------------------------------------------------------------------------
sub th_IRCConnManager {
    my ($IRCQueue) = @_;

    my $thr = threads->self();
    my $tid = $thr->tid();

    # Infinite loop... connect... reconnect... reconnect and so on...
    while(1) {
        print "Triying to establish connection to IRC. [".$conf{'IRC_SERVER'}.":".$conf{'IRC_PORT'}."]\n" if DEBUG;

        # Prepare IRC socket
        my $irc_proto = getprotobyname('tcp');
        socket(IRCSock, PF_INET, SOCK_STREAM, $irc_proto);
        my $irc_packet_ip = inet_aton($conf{'IRC_SERVER'});
        my $irc_sin = sockaddr_in($conf{'IRC_PORT'}, $irc_packet_ip);

        if(connect(IRCSock, $irc_sin)) {
            print "Xtreme Flash Policy IRC Bot connection successfull. [".$conf{'IRC_SERVER'}.":".$conf{'IRC_PORT'}."]\n" if DEBUG;

            my $prev_IRCSock = select(IRCSock); 
            $| = 1; # Don't buffer output
            select($prev_IRCSock);

            print IRCSock "NICK PolicyServ\n";
            print IRCSock "USER ".$conf{'IRC_USERNAME'}." 8 * :".$conf{'IRC_REALNAME'}."\n";

            # Enter IRC Stream thread
            my $thr_IRCStream = threads->create("th_IRCStream", \*IRCSock);
            my $tid_IRCStream = $thr_IRCStream->tid();
            print "-> IRC Stream UP on tid(".$tid_IRCStream.")\n" if DEBUG;

            # Enter IRC Queue thread
            my $thr_IRCQueue = threads->create("th_IRCQueue", \*IRCSock, $IRCQueue);
            my $tid_IRCQueue = $thr_IRCQueue->tid();
            print "-> IRC Queue UP on tid(".$tid_IRCQueue.")\n" if DEBUG;

            # Join stream until connection is alive
            $thr_IRCQueue->detach();
            $thr_IRCStream->join;

            # Don't work as expected...
            #$thr_IRCQueue->kill('KILL')->detach();
            $IRCQueue->enqueue("autodestroy()");

            print "Connection to IRC lost. Re-connect try in ".$conf{'IRC_RECONNECTSECS'}." secs...\n" if DEBUG;
            sleep $conf{'IRC_RECONNECTSECS'};
            next;

        } else {
            print "Unable to connect IRC. Next try in ".$conf{'IRC_RECONNECTSECS'}." secs...\n" if DEBUG;
            sleep $conf{'IRC_RECONNECTSECS'};
            next;
        }
    }
}

# -------------------------------------------------------------------------
# int &th_IRCStream(handler sock)
#
# Handles IRC Stream
# -------------------------------------------------------------------------
sub th_IRCStream {
    my ($IRCSock) = @_;

    while(my $IRCStream = <$IRCSock>) {
        $IRCStream = substr($IRCStream, 0, -2); # Remove last two carriage return characters

        #print "RecvIRC->".$IRCStream."<-\n" if DEBUG;

        # Ping reply
        # PING :IRC.looksharp.com.ar
        if($IRCStream =~ /^PING\s\:(\S*)$/) {
            print $IRCSock "PONG :".$1."\n";
            next;
        }
        
        # IRC Welcome
        # :IRC.looksharp.com.ar 001 PolicyServ :Welcome to the looksharp IRC Chat Network PolicyServ!Xtreme@xxx.xxx.xxx.xxx
        if($IRCStream =~ /^\:(\S+)\s001\s(\S+)\s\:(.*)$/ && $2 eq $conf{'IRC_NICK'}) {
            print $IRCSock $conf{'IRC_NICKSERV'}."\n";
            print $IRCSock "OPER ".$conf{'IRC_OPER'}."\n";
            print $IRCSock "MODE ".$2." ".$conf{'IRC_MODE'}."\n";
            print $IRCSock "AWAY ".$conf{'IRC_AWAY'}."\n";
            print $IRCSock "JOIN ".$conf{'IRC_CHANNEL'}."\n";
            next;
        }
        
        # Join our channel
        # :PolicyServ!Xtreme@policy.looksharp.com.ar JOIN :#services
        if($IRCStream =~ /^\:(\S+)\!(\S+)\@(\S+)\sJOIN\s\:([\#\&][a-zA-Z0-9\-\.]+)$/ && $4 eq $conf{'IRC_CHANNEL'} && $1 eq $conf{'IRC_NICK'}) {
            print $IRCSock "PRIVMSG ".$4." :Xtreme Flash Policy [NandOX+Endurance] v".VERSION." is UP!\n";
            print $IRCSock "PRIVMSG ".$4." :Trigger is: ".$conf{'IRC_FANTASY_PREFIX'}."\n";
            next;
        }
        
        # CTCP Version
        # :s4w!carpediem@Sanguis.meus.tibi.non.iam.perbibendus.sit PRIVMSG policyserv : VERSION
        if($IRCStream =~ /^\:(\S+)\!(\S+)\@(\S+)\sPRIVMSG\s(\S+)\s\:\SVERSION\S$/ && lc($4) eq lc($conf{'IRC_NICK'})) {
            print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :CTCP VERSION request by ".$1."\n";
            print $IRCSock "NOTICE ".$1." :".chr(1)."VERSION Xtreme Flash Policy [NandOX+Endurance] - v".VERSION." - http://www.nandox.com/".chr(1)."\n";
            next;
        }
        
        # !fantasy reply
        # :s4w!carpediem@Sanguis.meus.tibi.non.iam.perbibendus.sit PRIVMSG #services :!alive
        if($conf{'IRC_FANTASY'} && $IRCStream =~ /^\:(\S+)\!(\S+)\@(\S+)\sPRIVMSG\s([\#\&][a-zA-Z0-9\-\.]+)\s\:$conf{'IRC_FANTASY_PREFIX'}\s*(\S*)\s*(\S*)$/ && $4 eq $conf{'IRC_CHANNEL'}) {
            if(lc($5) eq lc('alive')) {
                print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :I'm fine ".$1."!\n";

            } elsif(lc($5) eq lc('stats')) {
                my @stats = &look_stats();

                foreach my $line (@stats) {
                    print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :".$line."\n";      
                }

            } else {
                print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :Options for ".$conf{'IRC_FANTASY_PREFIX'}." are: <alive|stats>\n";
            }
            next;
        }
        
        # Whois notify
        # :IRC.looksharp.com.ar NOTICE PolicyServ :*** s4w (carpediem@xxx.xxx.xxx.xxx) did a /whois on you.
        if($IRCStream =~ /^\:(\S+)\sNOTICE\s(\S+)\s\:\*\*\*\s(\S+)\s\((\S+\@\S+)\)\sdid\sa\s\/whois\son\syou\.$/ && $2 eq $conf{'IRC_NICK'}) {
            print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :".$3." (".$4.") did a /whois on me.\n";
            next;
        }
    }
    
    return(1);
}

# -------------------------------------------------------------------------
# int &th_IRCQueue(handler sock, handler queue)
#
# Handles IRC Queue
# -------------------------------------------------------------------------
sub th_IRCQueue {
    my ($IRCSock, $IRCQueue) = @_;

    my $thr = threads->self();
    my $tid = $thr->tid();

    # Thread 'cancellation' signal handler 
    #$SIG{'KILL'} = sub { 
    #    print "Killed IRC Queue tid(".$tid.")!\n" if DEBUG;
    #    threads->exit(); 
    #};
    # Don't work as expected...

    while (my $DataElement = $IRCQueue->dequeue) { 
        if($DataElement =~ /^autodestroy\(\)$/) {
            last;
        } else {
            print $IRCSock "PRIVMSG ".$conf{'IRC_CHANNEL'}." :".$DataElement."\n";
        }
    }

    return(1);
}

# -------------------------------------------------------------------------
# int &th_LogQueue(handler queue)
#
# Handles Log Queue
# -------------------------------------------------------------------------
sub th_LogQueue {
    my ($LogQueue) = @_;

    my $thr = threads->self();
    my $tid = $thr->tid();

    while (my $DataElement = $LogQueue->dequeue) { 
        open(OUT, ">>".$conf{'POLICY_LOGFILE'});
        my $timestamp = POSIX::strftime("%m/%d/%Y %H:%M:%S", localtime);
        print OUT $timestamp." - ".$DataElement."\n";
        close(OUT);
    }

    return(1);
}

# -------------------------------------------------------------------------
# int &look_floodconn_verify(ip address)
#
# Verify IP for flood connection and return true if is ok
# -------------------------------------------------------------------------
sub look_floodconn_verify {
    my ($addr, $IRCQueue, $LogQueue) = @_;
    my $time  = time;
    my $allow = 1;
    our %ip_blacklist;

    # First clean up our blacklist (time resets and expirations if enabled)
    my $secs2reset   = ($conf{'FLOODPRO_CONNTIME'} * 60);
    my $secs2expires = ($conf{'FLOODPRO_ADDREXPIRES'} * 60);

    foreach my $addr_key (keys %ip_blacklist) { # Blacklist expiration
        if($conf{'FLOODPRO_ADDREXPIRES'} > 0 && $ip_blacklist{$addr_key}{'blacklisted'}) {
            if(($time - $ip_blacklist{$addr_key}{'last_time'}) >= $secs2expires) {
                my $logmsg = "Blacklist: ".$addr." Removed! (Expired)";
                print $logmsg."\n" if DEBUG;
                $IRCQueue->enqueue($logmsg) if $conf{'IRC_LOG'};
                $LogQueue->enqueue($logmsg) if $conf{'POLICY_LOG'};

                delete $ip_blacklist{$addr_key};
            }
        } elsif(($time - $ip_blacklist{$addr_key}{'last_time'}) >= $secs2reset) { # Counting reset
            delete $ip_blacklist{$addr_key};
        }
    }

    # Now process current IP address counting
    if(!defined($ip_blacklist{$addr})) {
        $ip_blacklist{$addr}{'conn_count'}  = 1;
        $ip_blacklist{$addr}{'last_time'}   = $time;
        $ip_blacklist{$addr}{'blacklisted'} = 0;

        $allow = 1;

    } elsif($ip_blacklist{$addr}{'blacklisted'}) {
        $allow = 0;

    } else {
        $ip_blacklist{$addr}{'conn_count'}++;
        $ip_blacklist{$addr}{'last_time'}   = $time;

        if($ip_blacklist{$addr}{'conn_count'} > $conf{'FLOODPRO_CONNMAX'}) {
            $ip_blacklist{$addr}{'blacklisted'} = 1;
            my $logmsg = "Blacklist: ".$addr." Added! (".$ip_blacklist{$addr}{'conn_count'}." attempt/s in less than ".$conf{'FLOODPRO_CONNTIME'}." minute/s) ".($conf{'FLOODPRO_ADDREXPIRES'} > 0?"Expires in ".$conf{'FLOODPRO_ADDREXPIRES'}." minute/s":"Permanently");
            print $logmsg."\n" if DEBUG;
            $IRCQueue->enqueue($logmsg) if $conf{'IRC_LOG'};
            $LogQueue->enqueue($logmsg) if $conf{'POLICY_LOG'};

            # Trigger present?
            if($conf{'FLOODPRO_TRIGGER_CMD'}) {
                my $cmd = $conf{'FLOODPRO_TRIGGER_CMD'};
                $cmd =~ s/\<IP\_ADDRESS\>/$addr/m;
                $cmd =~ s/\<IP\_EXPIRE\>/$conf{'FLOODPRO_ADDREXPIRES'}/m;

                my $logmsg = "Executing: ".$cmd;
                print $logmsg."\n" if DEBUG;
                $IRCQueue->enqueue($logmsg) if $conf{'IRC_LOG'};
                $LogQueue->enqueue($logmsg) if $conf{'POLICY_LOG'};

                my @output = `$cmd`;

                if(@output) {
                    foreach my $line (@output) {
                        chomp($line);
                        $logmsg = "Output: ".$line;
                        print $logmsg."\n" if DEBUG;
                        $IRCQueue->enqueue($logmsg) if $conf{'IRC_LOG'};
                        $LogQueue->enqueue($logmsg) if $conf{'POLICY_LOG'};
                    }
                }
            }

            $allow = 0;
        }

    }

    #print "*** ip_blacklist dump:\n".Dumper(%ip_blacklist)."\n" if DEBUG;

    return($allow);
}

# -------------------------------------------------------------------------
# array &look_stats(void)
#
# Return some usefull stats
# -------------------------------------------------------------------------
sub look_stats {
    my @stats;
    my %peerpoolmethods = (0 => "QUEUE", 1 => "FORK", 2 => "THREAD");

    push(@stats, "-------------------------------------------------------------------------");
    push(@stats, "            *** Stats for NandOX Xtreme Flash Policy ***");
    push(@stats, "-");
    push(@stats, "Flash Policy Server is running on ".hostname);
    push(@stats, "-");
    push(@stats, "  Server Version is: ".VERSION);
    push(@stats, "     Pool Method is: ".$peerpoolmethods{$conf{'POLICY_PEERPOOLMETHOD'}});
    push(@stats, "        Log file is: ".($conf{'POLICY_LOG'}?"Enabled":"Disabled"));
    push(@stats, "Flood Protection is: ".($conf{'FLOODPRO_ENABLE'}?"Enabled":"Disabled"));
    push(@stats, "         IRC Bot is: ".($conf{'IRC_ENABLE'}?"Enabled":"Disabled"));

    if($conf{'FLOODPRO_ENABLE'}) {
        push(@stats, "-------------------------------------------------------------------------");
        push(@stats, "                   *** Flood Protection Blacklist ***");
        push(@stats, "-");
        push(@stats, "Maximum connections per IP: ".$conf{'FLOODPRO_CONNMAX'}." in ".$conf{'FLOODPRO_CONNTIME'}." minute/s");
        push(@stats, "Blacklist expiration is: ".$conf{'FLOODPRO_ADDREXPIRES'}." minute/s");
    }

    push(@stats, "-------------------------------------------------------------------------");
    push(@stats, "                      *** System memory usage ***");
    push(@stats, "-");

    foreach my $line (`$conf{"FREE_CMD"}`) {
        chomp($line);
        push(@stats, $line);
    }

    push(@stats, "-------------------------------------------------------------------------");
    push(@stats, "             *** Uptime, users and server load average ***");
    push(@stats, "-");

    foreach my $line (`$conf{"UPTIME_CMD"}`) {
        chomp($line);
        push(@stats, $line);
    }
    push(@stats, "-------------------------------------------------------------------------");

    return @stats;
}

# -------------------------------------------------------------------------
# int &sig_INT(void)
#
# INT Signal handler
# -------------------------------------------------------------------------

sub sig_INT {
    print "\nCaught ^C \n" if DEBUG;
    exit(0);
}

$SIG{'INT'} = 'sig_INT';

print "\n";
print "Xtreme Flash Policy [NandOX+Endurance] - v".VERSION."\n";
print "Coded by Hernando Furlan (aka Amaz|ng^)\n";
print "\n";
print "Copyright (C) 2012 by NandOX IRC Chat Network - Argentina\n";
print "http://www.nandox.com/\n";
print "\n";
print "Xtreme Flash Policy [NandOX+Endurance] comes with ABSOLUTELY NO WARRANTY.\n";
print "You may redistribute copies of Xtreme Flash Policy [NandOX+Endurance]\n";
print "under the terms of the GNU General Public License Version 2.\n";
print "For more information about these matters, see <http://www.gnu.org/licenses/gpl-2.0.txt>.\n";
print "\n";

# Security risk notice if running as root
if($conf{'LOOK_ROOTNOTICE'} && POSIX::cuserid() =~ /^root$/) {
    print "*********************************************************\n";
    print "                  SECURITY RISK NOTICE                   \n";
    print "\n";
    print "Running this this software as root may be a security risk\n";
    print "It's a very good idea to run under an *unprivileged* user\n";
    print "You are advised! and can disable this message by setting:\n";
    print "\n";
    print "      'LOOK_ROOTNOTICE' => 1, (at your config.pm)        \n";
    print "*********************************************************\n\n";
}

if(!$ARGV[0]) {
    die "  Usage: $0 <start|stop> [force]\n\n";
}

if($ARGV[0] eq 'start') {
    &looksharp_start();

} elsif($ARGV[0] eq 'stop') {
    &looksharp_stop();
}

print "\n";

exit(0);

=back

=head1 TERMS AND CONDITIONS

 Xtreme Flash Policy [NandOX+Endurance] 
 $Id: lookflashpolicy.pl,v 1.1 2012/11/01 00:10:17 nando Exp $

 Copyright (C) 2012 by NandOX IRC Chat Network <info@nandox.com>
 http://www.nandox.com/

 This file is part of Xtreme Flash Policy [NandOX+Endurance].

 Xtreme Flash Policy [NandOX+Endurance] is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 Xtreme Flash Policy [NandOX+Endurance] is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Xtreme Flash Policy [NandOX+Endurance]; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 or see <http://www.gnu.org/licenses/gpl-2.0.txt>.

=cut

=head1 VERSION

$Revision: 1.1 $ $Date: 2012/11/01 00:10:17 $

=cut
