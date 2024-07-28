package My::Protocols;

use strict;
use warnings;
use Data::Dumper;

use Exporter qw(import);

our @EXPORT_OK = qw(ethernet ip udp vlan8021q tcp arp mpls);

sub udp {
    my $bytes=shift; #pointer to udp packet bytes
    my $location=shift; #integer where in the bytes the udp data is found
    my %udp=();
    ($udp{'src_port'},$udp{'dst_port'},$udp{'len'},$udp{'checksum'},$udp{'payload'})=unpack("nnnna*",substr($$bytes,$location));
    $location+=8;
    return (\%udp,$location);
}

sub ethernet {
    my $bytes=shift; #pointer to udp packet bytes
    my $location=shift; #integer where in the bytes the udp data is found
    my %eth=();
    $eth{'dest_mac'} = join(':',unpack("(H2)*",substr($$bytes,$location,6)));
    $eth{'source_mac'} = join(':',unpack("(H2)*",substr($$bytes,$location+6,6)));
    $eth{'ether_type'} = unpack("H*",substr($$bytes,$location+12,2));
    $location+=14;
    return(\%eth,$location);
}

sub mpls {
    my $bytes=shift; #pointer to mpls packet bytes
    my $location=shift; #integer where in the bytes the mpls data is found
    my %mpls=();
    my $layer=0;
    my $eos=0;
    my $byte_length=length($$bytes);
    until ($eos == 1 or ($location + 4 > $byte_length)) {
        my $val=unpack("N",substr($$bytes,$location));
        $location+=4;
        $layer++;
        $mpls{$layer}{'label'}=$val >> 12;
        #print "here is my label: $mpls{$layer}{'label'}\n";
        $mpls{$layer}{'exp_bits'}=($val >> 9) & 0x7;
        $mpls{$layer}{'eos'}=($val >> 8) & 0x1;
        $eos=$mpls{$layer}{'eos'};
        $mpls{$layer}{'ttl'}=$val & 0x000000ff;
    }
    return(\%mpls,$location);
}

sub ip {
    my $bytes=shift; #pointer to udp packet bytes
    my $location=shift; #integer where in the bytes the udp data is found
    my %ip=();
    my $bits;
    ($bits,$ip{'tos'},$ip{'total_length'},$ip{'id'},$ip{'fragment_offset'},$ip{'ttl'},$ip{'protocol'},$ip{'cksum'},$ip{'source'},$ip{'destination'})=unpack("CCnnnCCnNN",substr($$bytes,$location));
    $ip{'source'}=&to_dotquad($ip{'source'});
    $ip{'destination'}=&to_dotquad($ip{'destination'});
    $ip{'version'}=($bits & 0xf0) >> 4;
    $ip{'header_length'}=($bits & 0x0f)*4;
    $ip{'flags'}=$ip{'fragment_offset'} >> 13;
    $ip{'fragment_offset'}=$ip{'fragment_offset'} << 3;
    $location+=$ip{'header_length'};
    return(\%ip,$location);
}

sub vlan8021q {
    my $bytes=shift; #pointer to vlan packet bytes
    my $location=shift; #integer where in the bytes the vlan data is found
    my %vlan=();
    (my $val,$vlan{'ether_type'})=unpack("n H4",substr($$bytes,$location));
    $vlan{'priority'}=$val >> 13;
    $vlan{'dei'}=($val >> 12) & 0x1;
    $vlan{'id'}=$val & 0x0fff;
    $location+=4;
    return(\%vlan,$location);
}

sub tcp {
    #not doing anything with TCP options in here
    my $bytes=shift; #pointer to tcp packet bytes
    my $location=shift; #integer where in the bytes the tcp data is found
    my %tcp=();
    ($tcp{'src_port'},$tcp{'dst_port'},$tcp{'seq_num'},$tcp{'ack_num'},my $tmp,$tcp{'win_size'},$tcp{'check_sum'},$tcp{'urgency'})=unpack("nnNNnnnn",substr($$bytes,$location));
    $tcp{'header_length'}=(($tmp & 0xf000) >> 12)*4;
    $tcp{'reserved'}=($tmp & 0x0f00) >> 8;
    $tcp{'flags'}=$tmp & 0x00ff;
    $location+=$tcp{'header_length'};
    $tcp{'payload'}=substr($$bytes,$location);
    return(\%tcp,$location);
}

sub arp {
    my $bytes=shift; #pointer to arp packet bytes
    my $location=shift; #integer where in the bytes the udp data is found
    my %arp=();
    #($arp{'hardware_type'},$arp{'protocol_type'},$arp{'hardware_size'},$arp{'op_code'},$arp{'sender_mac'},$arp{'sender_IP'},$arp{'target_mac'},$arp{'target_IP'})=unpack("nnCCnH12H8H12H8",substr($$bytes,$location));
    ($arp{'hardware_type'},$arp{'protocol_type'},$arp{'hardware_size'},$arp{'protocol_size'},$arp{'op_code'},$arp{'sender_mac'},$arp{'sender_IP'},$arp{'target_mac'},$arp{'target_IP'})=unpack("nH4CCnH12NH12N",substr($$bytes,$location));
    $location+=28;
    $arp{'sender_IP'}=&to_dotquad($arp{'sender_IP'});
    $arp{'target_IP'}=&to_dotquad($arp{'target_IP'});
    return(\%arp,$location);
}

sub to_dotquad {
    my $num=shift;
    my ($a,$b,$c,$d);
    $a = $num >> 24 & 255;
    $b = $num >> 16 & 255;
    $c = $num >>  8 & 255;
    $d = $num & 255;
    return ("$a.$b.$c.$d");
}
