package pf::firewallsso;

=head1 NAME

pf::web::firewallsso

=cut

=head1 DESCRIPTION

pf::web::firewall. 

=cut

use strict;
use warnings;

use Log::Log4perl;
use pf::client::jsonrpc;

=head1 SUBROUTINES

=over

=item new

=cut

sub new {
   my $logger = Log::Log4perl::get_logger("pf::firewallsso");
   $logger->debug("instantiating new pf::firewallsso");
   my ( $class, %argv ) = @_;
   my $self = bless {}, $class;
   return $self;
}

=item do_sso

Send the firewall sso update request to the webapi.

=cut

sub do_sso {
    my ($self, $method, $mac, $ip, $timeout) = @_;
    my $logger = Log::Log4perl::get_logger( ref($self) );

    my $client = pf::client::jsonrpc->new;

    my %data = (
       'method'           => $method,
       'mac'              => $mac,
       'ip'               => $ip,
       'timeout'          => $timeout
    );

    $client->notify('firewallsso', \%data );

}


=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2014 Inverse inc.

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

