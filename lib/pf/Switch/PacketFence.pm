package pf::Switch::PacketFence;

=head1 NAME

pf::Switch::PacketFence - Object oriented module to send local traps to snmptrapd

=head1 SYNOPSIS

The pf::Switch::PacketFence module implements an object oriented interface
to send local SNMP traps to snmptrapd

=head1 SUBROUTINES

List incomplete.

=cut

use strict;
use warnings;

use base ('pf::Switch');
use Log::Log4perl;
use Net::SNMP;
use HTTP::Headers;
use HTTP::Request;
use LWP::UserAgent;
use JSON;

sub description { 'PacketFence' }

sub sendLocalReAssignVlanTrap {
    my ($this, $switch, $ifIndex, $connection_type, $mac) = @_;
    my $switch_ip = $switch->{_ip};
    my $switch_id = $switch->{_id};
    my $logger = Log::Log4perl::get_logger( ref($this) );

    my %info = ('switch' => $switch_id, 'mac' => $mac, 'connection_type' => $connection_type, 'ifIndex' => $ifIndex);
    my $json = encode_json \%info;
    my $uri = 'http://127.0.0.1:9090/json';
    my $req = HTTP::Request->new( 'POST', $uri );
    $req->header( 'Content-Type' => 'application/json' );
    $req->header( 'Request' => 'ReAssign');
    $req->content( $json );

    my $lwp = LWP::UserAgent->new;
    $lwp->request( $req );

    return 1;

}

sub sendLocalDesAssociateTrap {
    my ($this, $switch, $mac, $connection_type) = @_;
    my $switch_ip = $switch->{_ip};
    my $switch_id = $switch->{_id};
    my $logger = Log::Log4perl::get_logger( ref($this) );

    my %info = ('switch' => $switch_id, 'mac' => $mac, 'connection_type' => $connection_type);
    my $json = encode_json \%info;
    my $uri = 'http://127.0.0.1:9090/json';
    my $req = HTTP::Request->new( 'POST', $uri );
    $req->header( 'Content-Type' => 'application/json' );
    $req->header( 'Request' => 'desAssociate');
    $req->content( $json );

    my $lwp = LWP::UserAgent->new;
    $lwp->request( $req );

    return 1;

}

=head2 sendLocalFirewallRequestTrap

Sends a local trap meant to trigger firewall changes in pfsetvlan

=cut

sub sendLocalFirewallRequestTrap {
    my ($this, $switch, $mac) = @_;
    my $switch_ip = $switch->{_ip};
    my $switch_id = $switch->{_id};
    my $logger = Log::Log4perl::get_logger( ref($this) );

    my %info = ('switch' => $switch_id, 'mac' => $mac);
    my $json = encode_json \%info;
    my $uri = 'http://127.0.0.1:9090/json';
    my $req = HTTP::Request->new( 'POST', $uri );
    $req->header( 'Content-Type' => 'application/json' );
    $req->header( 'Request' => 'firewall');
    $req->content( $json );

    my $lwp = LWP::UserAgent->new;
    $lwp->request( $req );

    return 1;

}


=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2013 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:

