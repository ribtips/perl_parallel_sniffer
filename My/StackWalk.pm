package My::StackWalk;

# This is a module to handle the reading of the pcap and its structure.  Basically the global header and the packet headers.

use My::Protocols qw(ethernet ip udp vlan8021q tcp arp mpls);
use Data::Dumper;

use Exporter qw(import);

our @EXPORT_OK=qw(stackwalk);

my %link_layer = (
    "1" => \&ethernet_layer,
);

my %layer_2 = (
    "0800" => \&ip_layer,
    "0806" => \&arp_layer,
    "8100" => \&vlan8021q_layer,
    "8847" => \&mpls_layer,
);

my %layer_3 = (
    6   => \&tcp_layer,
    17  => \&udp_layer,
);

sub stackwalk {
    my $payload=shift;
    my $location=shift;
    my $dlt=shift;
    my $layer=0;
    my %struct=();
    if (exists($link_layer{$dlt})) {
        $link_layer{$dlt}($payload,$location,\%struct,$layer);
    }
    print Dumper %struct;
    my $description=&print_struct_info(\%struct);
    return (\%struct,$description);
}

sub print_struct_info {
    my $struct=shift;
    my @structure;
    foreach my $layer (sort {$a<=>$b} keys %{$struct}) {
        push @structure,"$$struct{$layer}{'name'}:$$struct{$layer}{'info'}|";    
    }
    return(join"",@structure);
}

sub vlan8021q_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $vlan,$location)=vlan8021q($payload,$location);
    $$struct{$layer}{'name'}="VLAN8021q";
    $$struct{$layer}{'header'}=$vlan;
    if (exists($layer_2{$$vlan{'ether_type'}})) {
        $$struct{$layer}{'info'}="$$vlan{'id'}";
        $layer_2{$$vlan{'ether_type'}}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}="$$vlan{'id'}|$$vlan{'ether_type'}-NextLayerUnknown";
    }
}

sub mpls_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $mpls,$location)=mpls($payload,$location);
    $$struct{$layer}{'name'}="MPLS";
    $$struct{$layer}{'header'}=$mpls;

    my $mpls_label="";
    foreach my $layer (sort {$a<=>$b} keys %{$mpls}) {
        $mpls_label=$mpls_label."-".$$mpls{$layer}{'label'};
    }

    if (unpack("H2",substr($$payload,$location)) eq "45") {
        #print "Should probably throw this to IPv4...$mpls_label\n";
        $$struct{$layer}{'info'}=$mpls_label;
        $layer_2{"0800"}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}=$mpls_label."NextLayerUnknown";
    }

}

sub arp_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $arp,$location)=arp($payload,$location);
    $$struct{$layer}{'name'}="ARP";
    $$struct{$layer}{'header'}=$arp;
    $$struct{$layer}{'info'}="$$arp{'sender_IP'}-$$arp{'target_IP'}";
}

sub tcp_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $tcp,$location)=tcp($payload,$location);
    $$struct{$layer}{'name'}="TCP";
    $$struct{$layer}{'header'}=$tcp;
    $$struct{$layer}{'info'}="$$tcp{'src_port'}-$$tcp{'dst_port'}:$$tcp{'flags'}";
}

sub udp_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $udp,$location)=udp($payload,$location);
    $$struct{$layer}{'name'}="UDP";
    $$struct{$layer}{'header'}=$udp;
    $$struct{$layer}{'info'}="$$udp{'src_port'}-$$udp{'dst_port'}";
}

sub ethernet_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $eth,$location)=ethernet($payload,$location);
    $$struct{$layer}{'name'}="Ethernet";
    $$struct{$layer}{'header'}=$eth;
    #    print Dumper %{$struct};
    if (exists($layer_2{$$eth{'ether_type'}})) {
        $$struct{$layer}{'info'}="$$eth{'source_mac'}-$$eth{'dest_mac'}";
        $layer_2{$$eth{'ether_type'}}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}="$$eth{'source_mac'}-$$eth{'dest_mac'}|$$eth{'ether_type'}-NextLayerUnknown";
    }
}

sub ip_layer {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    (my $ip,$location)=ip($payload,$location);
    $$struct{$layer}{'name'}="IP";
    $$struct{$layer}{'header'}=$ip;
    if (exists($layer_3{$$ip{'protocol'}})) {
        $$struct{$layer}{'info'}="$$ip{'source'}-$$ip{'destination'}";
        $layer_3{$$ip{'protocol'}}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}="$$ip{'source'}-$$ip{'destination'}|$$ip{'protocol'}-NextLayerUnknown";
    }
     
}
