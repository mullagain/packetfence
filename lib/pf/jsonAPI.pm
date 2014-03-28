package pf::jsonAPI;

=head1 NAME

WebAPI - Apache mod_perl wrapper to PFAPI (below).

=cut

use strict;
use warnings;

use Apache2::RequestRec;
use Apache2::Request;
use Apache2::RequestIO;
use Apache2::RequestUtil;

use Apache2::Const -compile => qw(OK);
use Log::Log4perl;
use JSON;
use Data::Dumper;

use pf::config;
use pf::SwitchFactory;

Log::Log4perl->init_and_watch("$conf_dir/log.conf", $LOG4PERL_RELOAD_TIMER);
Log::Log4perl::MDC->put('proc', 'pf::jsonAPI');

sub handler {
    my ($r) = @_;
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    if (defined($r->headers_in->{Request})) {
        $r->user($r->headers_in->{Request});
    }

    my $cont_len;
    $cont_len = $r->headers_in->{'Content-length'};

    my $content = "";
    if ( $cont_len > 0 ) {
        my $buf;

        $content .= $buf while ( $r->read( $buf, $cont_len ) > 0 );
    }

    my $text = decode_json($content);
    $logger->warn($content);
    $logger->warn(Dumper $text);


    $r->pnotes->{info} = $text;
    $r->handler('modperl');
    $r->set_handlers(PerlCleanupHandler => dispatch_request($r->headers_in->{Request}));
    return Apache2::Const::OK;
}

sub dispatch_request {
    my ($request) = @_;
    my $logger = Log::Log4perl::get_logger('pf::jsonAPI');

    my $key = {
        ReAssign => \&ReAssignVlan,
        desAssociate  => \&desAssociate,
        firewall => \&firewall,
    };
    return $key->{$request};
}

sub ReAssignVlan {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};
    my $switch = pf::SwitchFactory->getInstance()->instantiate($info->{'switch'});

    if (defined($info->{'connection_type'}) && ($info->{'connection_type'} == $WIRED_802_1X || $info->{'connection_type'} == $WIRED_MAC_AUTH) ) {
        my ($switchdeauthMethod, $deauthTechniques) = $switch->wiredeauthTechniques($switch->{_deauthMethod},$info->{'connection_type'});
        $deauthTechniques->($info->{'switch'},$info->{'ifIndex'},$info->{'mac'});
#    } else {
#
#        my @locationlog = locationlog_view_open_switchport_no_VoIP($info->{'switch'},$info->{'ifIndex'});
#        if ((@locationlog) && ( scalar(@locationlog) > 0 ) && ( $locationlog[0]->{'mac'} ne '' )) {
#            my $mac = $locationlog[0]->{'mac'};
#
#            if ( $switch->isPortSecurityEnabled($switch_port) ) {
#                $logger->info( "security traps are configured on " . $switch->{_id}
#                    . " ifIndex $switch_port. Re-assigning VLAN for $mac"
#                );

#                my $hasPhone = $switch->hasPhoneAtIfIndex($switch_port);
#                node_determine_and_set_into_VLAN( $mac, $switch, $switch_port, $connection_type );

#                # TODO extract that behavior in a method call in pf::vlan so it can be overridden easily
#                if ( !$hasPhone ) {
#                    $logger->info(
#                        "no VoIP phone is currently connected at " . $switch->{_id} . " ifIndex $switch_port. " .
#                        "Flipping port admin status"
#                    );
#                    $switch->bouncePort( $switch_port );
#
#                } else {
#                    my @violations = violation_view_open_desc($mac);
#                    if ( scalar(@violations) > 0 ) {
#                        my %message;
#                        $message{'subject'} = "VLAN isolation of $mac behind VoIP phone";
#                        $message{'message'} = "The following computer has been isolated behind a VoIP phone\n";
#                        $message{'message'} .= "MAC: $mac\n";
#                        my $node_info = node_view($mac);
#                        $message{'message'} .= "Owner: " . $node_info->{'pid'} . "\n";
#                        $message{'message'} .= "Computer Name: " . $node_info->{'computername'} . "\n";
#                        $message{'message'} .= "Notes: " . $node_info->{'notes'} . "\n";
#                        $message{'message'} .= "Switch: " . $switch->{_id} . "\n";
#                        $message{'message'} .= "Port (ifIndex): " . $switch_port . "\n\n";
#                        $message{'message'} .= "The violation details are\n";

#                        foreach my $violation (@violations) {
#                            $message{'message'} .= "Description: " . $violation->{'description'} . "\n";
#                            $message{'message'} .= "Start: " . $violation->{'start_date'} . "\n";
#                        }
#                        $logger->info("sending email to admin regarding isolation of $mac behind VoIP phone");
#                        pfmailer(%message);
#                    }
#                    else {
#                        $logger->warn("VLAN changed and $mac is behind VoIP phone. Not bouncing the port!");
#                    }
#                }
#            } else {
#                $logger->info(
#                    "no security traps are configured on " . $switch->{_id} . " ifIndex $switch_port. " .
#                    "Flipping port admin status"
#                );
#                $switch->bouncePort( $switch_port );
#            }
#        } else {
#            $logger->warn(
#                "received reAssignVlan trap on $switch_id ifIndex $switch_port but can't determine non VoIP MAC"
#            );
#        }
    }
}

sub desAssociate {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};
    my $switch = pf::SwitchFactory->getInstance()->instantiate($info->{'switch'});

    my ($switchdeauthMethod, $deauthTechniques) = $switch->deauthTechniques($switch->{'_deauthMethod'},$info->{'connection_type'});

    $deauthTechniques->($switch,$info->{'mac'});
}

sub firewall {
    my $r = (shift);
    my $logger = Log::Log4perl->get_logger('pf::jsonAPI');

    my $info = $r->pnotes->{info};

    # verify if firewall rule is ok
    my $inline = new pf::inline::custom();
    $inline->performInlineEnforcement($info->{'mac'});
}

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

