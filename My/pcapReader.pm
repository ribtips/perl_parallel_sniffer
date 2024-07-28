package My::pcapReader;

# This is a module to handle the reading of the pcap and its structure.  Basically the global header and the packet headers.

use Exporter qw(import);

our @EXPORT_OK=qw(interpret_global_header interpret_packet_header);

sub interpret_packet_header {
    my $bytes = shift;
    my %ph=();
    ($ph{'ts_sec'},$ph{'ts_usec'},$ph{'incl_len'},$ph{'orig_len'})=unpack("LLLL",$$bytes);
    return \%ph;
}

sub interpret_global_header {
    my $bytes = shift;
    my %gh=();
    ($gh{'magic_number'},$gh{'version_major'},$gh{'version_minor'},$gh{'timezone'},$gh{'sigfigs'},$gh{'snaplen'},$gh{'dlt'})=unpack("LSSlLLL",$$bytes);
    return \%gh;
}
