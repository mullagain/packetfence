package captiveportal::PacketFence::Controller::Signup;
use Moose;
use namespace::autoclean;
use Date::Format qw(time2str);
use pf::log;
use pf::config;
use pf::temporary_password 1.11;
use pf::util;
use pf::web qw(i18n ni18n i18n_format render_template);
use pf::web::constants;
use pf::web::util;
use pf::web::guest;
use pf::email_activation;
use pf::sms_activation;
use pf::Authentication::constants;
use pf::Authentication::Action;
use pf::authentication;
use List::MoreUtils qw(uniq any);
use Readonly;
use POSIX;
use URI::Escape qw(uri_escape);
use pf::iplog;
use pf::node;
use pf::person qw(person_modify);
use pf::violation;
use pf::web;

# called last to allow redefinitions
use pf::web::custom;

BEGIN { extends 'captiveportal::Base::Controller'; }

=head1 NAME

captiveportal::PacketFence::Controller::Signup - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut

=head2 index

=cut

sub begin : Private {
    my ( $self, $c ) = @_;

    # if we can resolve the MAC we are in on-site self-registration
    # if we can't resolve it and preregistration is disabled, generate an error
}

=head2 checkPreregistration

TODO: documention

=cut

sub checkPreregistration : Private {
    my ( $self, $c ) = @_;
    my $request = $c->request;

    # forced pre-registration overrides anything previously set (or not set)
    if ( defined( $request->param("preregistration") )
        && $request->param("preregistration") eq 'forced' ) {
        $c->session->{"preregistration"} = $TRUE;
    }

}


=head2 setupGuestMac

TODO: documention

=cut

sub setupGuestMac : Private {
    my ( $self, $c ) = @_;
    my $portalSession = $c->portalSession;
    # Clearing the MAC if in pre-registration
    # Warning: this assumption is important for preregistration
    if ( $c->session->{"preregistration"} ) {
        $portalSession->guestNodeMac(undef);
    }

    # Assigning MAC as guest MAC
    # FIXME quick and hackish fix for #1505. A proper, more intrusive, API changing, fix should hit devel.
    else {
        $portalSession->guestNodeMac( $portalSession->clientMac() );
    }
}

sub index : Path : Args(0) {
    my ( $self, $c ) = @_;
    $c->forward( CaptivePortal => 'validateMac');
    $c->forward('checkGuestModes');
    $c->forward('checkPreregistration');
    $c->forward('setupGuestMac');
    my $mode    = $c->request->param("mode");
    if ( $mode && $mode eq $pf::web::guest::GUEST_REGISTRATION ) {
        $c->forward('validateSelfRegistration');
        $c->forward('doSelfRegistration');
    }
    $c->forward('showSelfRegistrationPage');
}

=head2 doSelfRegistration

TODO: documention

=cut

sub doSelfRegistration : Private {
    my ( $self, $c ) = @_;
    my $request = $c->request;
    my $profile = $c->profile;
    if (   $request->param('by_email')
        && $profile->guestModeAllowed($SELFREG_MODE_EMAIL) ) {
        $c->detach('doEmailSelfRegistration');
    } elsif ( $request->param('by_sponsor')
        && $profile->guestModeAllowed($SELFREG_MODE_SPONSOR) ) {
        $c->detach('doSponsorSelfRegistration');
    } elsif ( $request->param('by_sms')
        && $profile->guestModeAllowed($SELFREG_MODE_SMS) ) {
        $c->detach('doSmsSelfRegistration');
    }
    $self->validationError( $c, $GUEST::ERROR_INVALID_FORM );
    return;
}

=head2 doEmailSelfRegistration

TODO: documention

=cut

sub doEmailSelfRegistration : Private {
    my ( $self, $c ) = @_;
    my $logger        = get_logger;
    my $portalSession = $c->portalSession;
    my $session       = $c->session;
    my $profile       = $c->profile;
    my %info;
    $logger->info(
        "registering "
          . (
            $session->{preregistration}
            ? 'a remote'
            : $portalSession->clientMac()
          )
          . " guest by email"
    );

    my $pid   = $session->{guest_pid};
    my $email = $session->{email};
    $info{'pid'} = $pid;

    # fetch role for this user
    my $email_type =
      pf::Authentication::Source::EmailSource->getDefaultOfType;
    my $source      = $profile->getSourceByType($email_type);
    my $auth_params = {
        'username'   => $pid,
        'user_email' => $email
    };
    $info{'category'} =
      &pf::authentication::match( $source->{id}, $auth_params,
        $Actions::SET_ROLE );

    # form valid, adding person (using modify in case person already exists)
    person_modify(
        $pid,
        (   'firstname' => $session->{firstname},
            'lastname'  => $session->{lastname},
            'company'   => $session->{company},
            'email'     => $email,
            'telephone' => $session->{phone},
            'notes'     => 'email activation. Date of arrival: '
              . time2str( "%Y-%m-%d %H:%M:%S", time ),
        )
    );

    # if we are on-site: register the node
    if ( !$session->{preregistration} ) {

        # Use the activation timeout to set the unregistration date
        my $timeout = normalize_time( $source->{email_activation_timeout} );
        $info{'unregdate'} = POSIX::strftime( "%Y-%m-%d %H:%M:%S",
            localtime( time + $timeout ) );
        $logger->debug( "Registration for guest "
              . $pid
              . " is valid until "
              . $info{'unregdate'} );
        $c->forward('CaptivePortal' => 'webNodeRegister',[$pid, %info]);

    }

    # add more info for the activation email
    %info = prepareEmailGuestActivationInfo( $c->session, %info );

    # TODO this portion of the code should be throttled to prevent malicious intents (spamming)
    my ( $auth_return, $err, $errargs_ref ) =
      pf::email_activation::create_and_email_activation_code(
        $portalSession->guestNodeMac(),
        $pid, $email,
        (     $session->{preregistration}
            ? $pf::web::guest::TEMPLATE_EMAIL_EMAIL_PREREGISTRATION
            : $pf::web::guest::TEMPLATE_EMAIL_GUEST_ACTIVATION
        ),
        $pf::email_activation::GUEST_ACTIVATION,
        %info
      );

    if ( !$session->{preregistration} ) {

        # does the necessary captive portal escape sequence (violations, provisionning, etc.)
        $c->detach( CaptivePortal => 'endPortalSession') if $auth_return;
    }

    # pregistration: we show a confirmation page
    $c->stash(
        template => $pf::web::guest::PREREGISTRATION_CONFIRMED_TEMPLATE,
        'mode' => $SELFREG_MODE_EMAIL
    );
    $c->detach;
}


sub prepareEmailGuestActivationInfo : Private {
    my ( $session, %info ) = @_;

    $info{'firstname'} = $session->{"firstname"};
    $info{'lastname'} = $session->{"lastname"};
    $info{'telephone'} = $session->{"phone"};
    $info{'company'} = $session->{"company"};
    $info{'subject'} = i18n_format("%s: Email activation required", $Config{'general'}{'domain'});

    return %info;
}

=head2 doSponsorSelfRegistration

TODO: documention

=cut

sub doSponsorSelfRegistration : Private {
    my ( $self, $c ) = @_;
    my $logger        = get_logger;
    my $profile       = $c->profile;
    my $request       = $c->request;
    my $portalSession = $c->portalSession;
    my %info;
    $logger->info(
        "registering "
          . (
            $c->session->{preregistration}
            ? 'a remote'
            : $portalSession->clientMac()
          )
          . " guest through a sponsor"
    );

    my $pid   = $c->session->{'guest_pid'};
    my $email = $c->session->{"email"};
    $info{'pid'} = $pid;

    # form valid, adding person (using modify in case person already exists)
    person_modify(
        $pid,
        (   'firstname' => $c->session->{"firstname"},
            'lastname'  => $c->session->{"lastname"},
            'company'   => $c->session->{'company'},
            'email'     => $email,
            'telephone' => $c->session->{"phone"},
            'sponsor'   => $c->session->{"sponsor"},
            'notes'     => 'sponsored guest. Date of arrival: '
              . time2str( "%Y-%m-%d %H:%M:%S", time )
        )
    );
    $logger->info( "Adding guest person " . $c->session->{'guest_pid'} );

    my $sponsor_type =
      pf::Authentication::Source::SponsorEmailSource->getDefaultOfType;
    my $source      = $profile->getSourceByType($sponsor_type);
    my $auth_params = {
        'username'   => $pid,
        'user_email' => $email
    };

    # fetch role for this user
    $info{'category'} =
      &pf::authentication::match( $source->{id}, $auth_params,
        $Actions::SET_ROLE );

    # Setting access timeout and role (category) dynamically
    $info{'unregdate'} =
      &pf::authentication::match( $source->{id}, $auth_params,
        $Actions::SET_ACCESS_DURATION );

    if ( defined $info{'unregdate'} ) {
        $info{'unregdate'} = POSIX::strftime( "%Y-%m-%d %H:%M:%S",
            localtime( time + normalize_time( $info{'unregdate'} ) ) );
    } else {
        $info{'unregdate'} =
          &pf::authentication::match( $source->{id}, $auth_params,
            $Actions::SET_UNREG_DATE );
    }

    # set node in pending mode
    $info{'status'} = $pf::node::STATUS_PENDING;

    if ( !$c->session->{"preregistration"} ) {

        # modify the node
        node_modify( $portalSession->clientMac(), %info );
    }

    $info{'cc'} = $Config{'guests_self_registration'}{'sponsorship_cc'};

    # fetch more info for the activation email
    # this is meant to be overridden in pf::web::custom with customer specific needs
    foreach my $key (qw(firstname lastname telephone company sponsor)) {
        $info{$key} = $c->session->{$key};
    }
    $info{is_preregistration} = $c->session->{preregistration};
    $info{'subject'} =
      i18n_format( "%s: Guest access request", $Config{'general'}{'domain'} );

    # TODO this portion of the code should be throttled to prevent malicious intents (spamming)
    my ( $auth_return, $err, $errargs_ref ) =
      pf::email_activation::create_and_email_activation_code(
        $portalSession->guestNodeMac(),
        $pid,
        $info{'sponsor'},
        $pf::web::guest::TEMPLATE_EMAIL_SPONSOR_ACTIVATION,
        $pf::email_activation::SPONSOR_ACTIVATION,
        %info
      );

    # on-site: redirection will show pending page (unless there's a violation for the node)
    if ( !$c->session->{"preregistration"} ) {
        $c->response->redirect( '/captive-portal?destination_url='
              . uri_escape( $c->stash->{destination_url} ) );

    }

    # pregistration: we show a confirmation page
    else {
        $c->stash(
            template => $pf::web::guest::PREREGISTRATION_CONFIRMED_TEMPLATE,
            'mode'   => $SELFREG_MODE_SPONSOR
        );
    }
    $c->detach;
}    # SPONSOR

=head2 doSmsSelfRegistration

TODO: documention

=cut

sub doSmsSelfRegistration : Private {
    my ( $self, $c ) = @_;
    my $portalSession = $c->portalSession;
    if ( $c->session->{"preregistration"} ) {
        $self->showError($c, i18n("Registration in advance by SMS is not supported.") );
    }
    my %info;
    my $profile        = $c->profile;
    my $request        = $c->request;
    my $logger         = get_logger;
    my $mac            = $portalSession->clientMac;
    my $phone          = $request->param("phone");
    my $mobileprovider = $request->param("mobileprovider");

    # User chose to register by SMS
    $logger->info("registering $mac  guest by SMS $phone @ $mobileprovider");
    my ( $auth_return, $err, $errargs_ref ) =
      sms_activation_create_send( $portalSession->guestNodeMac(),
        $phone, $mobileprovider );
    if ($auth_return) {

        my $pid   = $c->session->{'guest_pid'};
        my $phone = $c->session->{"phone"};
        $info{'pid'} = $pid;

        # form valid, adding person (using modify in case person already exists)
        $logger->info("Adding guest person $pid ($phone)");
        person_modify(
            $pid,
            (   map { $_ => $c->session->{$_} }
                  qw(firstname lastname company  email)
            ),
            (   'telephone' => $phone,
                'notes'     => 'sms confirmation. Date of arrival: '
                  . time2str( "%Y-%m-%d %H:%M:%S", time ),
            )
        );

        $logger->info("redirecting to mobile confirmation page");

        # fetch role for this user
        my $sms_type =
          pf::Authentication::Source::SMSSource->getDefaultOfType;
        my $source      = $profile->getSourceByType($sms_type);
        my $auth_params = {
            'username'    => $pid,
            'phonenumber' => $phone
        };
        $info{'category'} =
          &pf::authentication::match( $source->{id}, $auth_params,
            $Actions::SET_ROLE );

        # set node in pending mode with the appropriate role
        $info{'status'} = $pf::node::STATUS_PENDING;
        node_modify( $portalSession->clientMac(), %info );
        $c->detach( 'Activate::Sms' => 'showSmsConfirmation' );

    } else {
        $self->validationError( $c, $err );
    }
}    # SMS

sub checkGuestModes : Private {
    my ( $self, $c ) = @_;
    if ( @{ $c->profile->getGuestModes } == 0 ) {
        $c->response->redirect( "/captive-portal?destination_url="
              . uri_escape( $c->stash->{destination_url} ) );
        $c->detach;
    }
}

=head2 validateSelfRegistration

TODO: documention

=cut

sub validateSelfRegistration : Private {
    my ( $self, $c ) = @_;
    $c->forward('validatePreregistration');
    $c->forward('validateMandatoryFields');
    $c->forward('validateByEmailSource');
    $c->forward('validateBySponsorSource');
    $c->forward('setupSelfRegistrationSession');
}


=head2 setupSelfRegistrationSession

TODO: documention

=cut

sub setupSelfRegistrationSession : Private {
    my ( $self, $c ) = @_;
    my $request = $c->request;
    $c->session->{firstname} = $request->param("firstname");
    $c->session->{lastname}  = $request->param("lastname");
    $c->session->{company}   = $request->param("organization");
    $c->session->{phone} =
      pf::web::util::validate_phone_number( $request->param("phone") );
    $c->session->{email}   = lc( $request->param("email") );
    $c->session->{sponsor} = lc( $request->param("sponsor_email") );

    # guest pid is configurable (defaults to email)
    $c->session->{guest_pid} =
      $c->session->{ $Config{'guests_self_registration'}{'guest_pid'} };
}


=head2 validatePreregistration

TODO: documention

=cut

sub validatePreregistration : Private {
    my ( $self, $c ) = @_;
    if ( $c->session->{preregistration}
        && isdisabled(
            $Config{'guests_self_registration'}{'preregistration'} ) ) {
        $self->validationError( $c, $GUEST::ERROR_PREREG_NOT_ALLOWED );
    }
}

=head2 validateBySponsorSource

TODO: documention

=cut

sub validateBySponsorSource : Private {
    my ( $self, $c ) = @_;
    my $profile = $c->profile;
    my $request = $c->request;
    if ( $request->param('by_sponsor') ) {
        my $sponsor_email = lc( $request->param('sponsor_email') );
        my ( $username, $source_id ) =
          &pf::authentication::username_from_email($sponsor_email);
        unless (
            defined $username
            && defined &pf::authentication::match(
                $source_id, { username => $username },
                $Actions::MARK_AS_SPONSOR
            )
          ) {
            $self->validationError( $c,
                $GUEST::ERROR_EMAIL_UNAUTHORIZED_AS_GUEST,
                $sponsor_email );
        }
    }
}

=head2 validateByEmailSource

TODO: documention

=cut

sub validateByEmailSource : Private {
    my ( $self, $c ) = @_;
    my $profile = $c->profile;
    my $request = $c->request;
    my $email_type =
      pf::Authentication::Source::EmailSource->getDefaultOfType;
    my $source      = $profile->getSourceByType($email_type);
    my $localdomain = $Config{'general'}{'domain'};
    if (   $source
        && isdisabled( $source->{allow_localdomain} )
        && $request->param('email') =~ /[@.]$localdomain$/i ) {
        $self->validationError( $c,
            $GUEST::ERROR_EMAIL_UNAUTHORIZED_AS_GUEST, $localdomain );
    }
}

sub validationError {
    my ( $self, $c, $error_code, @error_args ) = @_;
    $c->stash->{'txt_validation_error'} =
      i18n_format( $GUEST::ERRORS{$error_code}, @error_args );
    $c->detach('showSelfRegistrationPage');
}

=head2 validateMandatoryFields

TODO: documention

=cut

sub validateMandatoryFields : Private {
    my ( $self, $c ) = @_;
    my $request = $c->request;
    my ( $error_code, @error_args );
    my @mandatory_fields = split( /\s*,\s*/,
        $Config{'guests_self_registration'}{'mandatory_fields'} );
    my $by_email   = $request->param('by_email');
    my $by_sms     = $request->param('by_sms');
    my $by_sponsor = $request->param('by_sponsor');
    push @mandatory_fields, qw(email)         if ( defined $by_email );
    push @mandatory_fields, qw(sponsor_email) if ( defined $by_sponsor );
    push @mandatory_fields, qw(phone mobileprovider)
      if ( defined $by_sms );
    @mandatory_fields = uniq @mandatory_fields;
    my %mandatory_fields = map { $_ => undef } @mandatory_fields;
    my @missing_fields = grep { !$request->param($_) } @mandatory_fields;

    if (@missing_fields) {
        $error_code = $GUEST::ERROR_MISSING_MANDATORY_FIELDS;
        @error_args = ( join( ", ", map { i18n($_) } @missing_fields ) );
    } elsif ( exists $mandatory_fields{email}
        && !pf::web::util::is_email_valid( $request->param('email') ) ) {
        $error_code = $GUEST::ERROR_ILLEGAL_EMAIL;
    } elsif ( exists $mandatory_fields{phone}
        && !pf::web::util::validate_phone_number( $request->param('phone') ) )
    {
        $error_code = $GUEST::ERROR_ILLEGAL_PHONE;
    } elsif ( !length( $request->param("aup_signed") ) ) {
        $error_code = $GUEST::ERROR_AUP_NOT_ACCEPTED;
    }
    if ( defined $error_code && $error_code != 0 ) {
        $self->validationError( $c, $error_code, @error_args );
    }
}

=head2 authenticateSelfRegistration

TODO: documention

=cut

sub authenticateSelfRegistration : Private {
    my ( $self, $c ) = @_;
    return;
}

sub showSelfRegistrationPage : Private {
    my ( $self, $c ) = @_;
    my $logger  = get_logger;
    my $profile = $c->profile;
    my $request = $c->request;

    my $sms_type =
      pf::Authentication::Source::SMSSource->meta->get_attribute('type')
      ->default;
    my $source     = $profile->getSourceByType($sms_type);
    my $guestModes = $profile->getGuestModes;

    $c->stash(
        post_uri            => "$WEB::URL_SIGNUP?mode=guest-register",
        firstname           => $request->param("firstname") || '',
        lastname            => $request->param("lastname") || '',
        organization        => $request->param("organization") || '',
        phone               => $request->param("phone") || '',
        mobileprovider      => $request->param("mobileprovider") || '',
        email               => lc( $request->param("email") || '' ),
        sponsor_email       => lc( $request->param("sponsor_email") || '' ),
        sms_carriers        => sms_carrier_view_all($source),
        is_preregistration  => $c->session->{'preregistration'},
        sms_guest_allowed   => is_in_list( $SELFREG_MODE_SMS, $guestModes ),
        email_guest_allowed => is_in_list( $SELFREG_MODE_EMAIL, $guestModes ),
        sponsored_guest_allowed =>
          is_in_list( $SELFREG_MODE_SPONSOR, $guestModes ),
    );

    $c->stash( template => 'guest.html' );
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

__PACKAGE__->meta->make_immutable;

1;
