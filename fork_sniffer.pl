#!/usr/bin/perl

# A simple sniffer example that will print out the stack as it's happening...

use strict;
use warnings;
use FindBin;
use Data::Dumper;
use Net::Pcap;

use lib "$FindBin::Bin";
use My::pcapReader qw(interpret_global_header interpret_packet_header);
use My::StackWalk qw(stackwalk);
use My::Protocols qw(ethernet);

$|=1;
my $gh=pack("LSSlLLL",0xa1b2c3d4,2,4,0,0,65535,1);
my $errbuf;
my $pack_num=0;
my @packets=();
my @tmp_packets=();

&main;

sub main {
    my $device = pcap_lookupdev(\$errbuf);
    if (defined $errbuf) {die "Unable to find device: ",$errbuf;}
    print "My device is $device!\n";
    my $handle = pcap_open_live($device, 65534, 1, 0, \$errbuf);
    pcap_loop($handle, -1, \&process_packet, "for demo");
    pcap_close($handle);
}

sub process_packet {
    $pack_num++;
    my ($user, $header, $packet)=@_;
    &stuff_packet($header,$packet);
    print "I've read $pack_num packets...\r";
    if ($pack_num % 1000 == 0) {
        #@tmp_packets=splice @packets,0,1000;
        @tmp_packets=@packets;
        @packets=();
        my $pid = fork;
        if ($pid == 0) {
            &write_packets;
            exit;
        }
    }
}

sub stuff_packet {
    my ($hdr,$packet)=@_;
    my $header=pack("LLLL",$$hdr{'tv_sec'},$$hdr{'tv_usec'},$$hdr{'caplen'},$$hdr{'len'});
    push @packets,$header.$packet;
}

sub write_packets {
    print "Child process started...\n";
    open(my $out,">","/dev/shm/$pack_num-packets.cap");
    print $out $gh;
    foreach my $pack (@tmp_packets) {
        print $out $pack;
    }
    @tmp_packets=();
    close($out);
    print "Child process finished...wrote packets\n";
}

sub write_packets2 {
    my $pid;
    my $ret;
    if (!defined($pid=fork())) {
        die "Cannot fork a child: $!";
    }
    elsif ($pid==0) {
        print "Child process started...\n";
        open(my $out,">","/dev/shm/$pack_num-packets.cap");
        print $out $gh;
        print "going to sleep for a second...\n";
        sleep(2);
        foreach my $pack (@tmp_packets) {
            print $out $pack;
        }
        @tmp_packets=();
        close($out);
        print "Child process finished...wrote packets\n";
    }
    else {
        print "printed by parent...\n";
        $ret=waitpid($pid,0);
        print "Completed process id: $ret\n"
    }
}

