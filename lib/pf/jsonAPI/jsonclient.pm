package pf::jsonAPI::jsonclient;

=head1 NAME

pf::jsonAPI::jsonclient - Object to send json to jsonAPI

=cut

=head1 DESCRIPTION

pf::jsonAPI::jsonclient - Client to send json to jsonAPI

=cut

use strict;
use warnings;

use Log::Log4perl;
use pf::config qw(%Config);

use HTTP::Headers;
use HTTP::Request;
use JSON;
use LWP::UserAgent;
use MIME::Base64;


=head1 SUBROUTINES

=over

=item new

=cut

sub new {
   my $logger = Log::Log4perl::get_logger("pf::jsonAPI::jsonclient");
   $logger->debug("instantiating new pf::jsonAPI::jsonclient");
   my ( $class, %argv ) = @_;
   my $self = bless {}, $class;
   return $self;
}


=item
sub call_WebAPI

Makes an http call to the json webapi to deassociate, reassignvlan or change firewall status.

=cut

sub call_WebAPI {
    my ($self, $request, %info ) = @_;
    my $logger = Log::Log4perl::get_logger( ref(__PACKAGE__) );

    my $json = encode_json \%info;
    my $req = HTTP::Request->new( 'POST', $Config{'webservices'}{'url'}.'/json' );

    $req->push_header('Authorization' => "Basic " . encode_base64($Config{'webservices'}{'user'}.':'.$Config{'webservices'}{'password'})) if defined($Config{'webservices'}{'user'} ne '');
    $req->header( 'Content-Type' => 'application/json' );
    $req->header( 'Request'      => $request );
    $req->content($json);

    my $lwp = LWP::UserAgent->new;

    $logger->info("Calling WebAPI with $request request");
    $lwp->request($req);

    return 1;
}


=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

Minor parts of this file may have been contributed. See CREDITS.

=head1 COPYRIGHT

Copyright (C) 2005-2014 Inverse inc.

Copyright (C) 2005 Kevin Amorin

Copyright (C) 2005 David LaPorte

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

