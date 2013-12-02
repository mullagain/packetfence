package pf::stats;

use strict;
use DBI;
use Readonly;

use pf::util qw(oui_to_vendor);

Readonly::Scalar our $DATABASE                => './result.db';

=item new

Constructor.

=cut

sub new {
    my ( $class, @argv ) = @_;
    my $this = bless {}, $class;

    my $database = $argv[0] || $DATABASE;

    if (-e $database) {
        $this->stats_connect($database);
    } else {
        $this->stats_connect($database,1); 
    }
    return $this;
}

sub stats_connect {
    my($this,$database,$create) = @_;

    my $sqlite = DBI->connect(          
        "dbi:SQLite:dbname=$database", 
        "",
        "",
        { RaiseError => 1}
    ) or die $DBI::errstr;
    $this->{'sqlite'} = $sqlite;

    if (defined ($create)) {
        $this->create_tables();
    }
}

sub stats_dns {
    my($this,$mac,$domain) = @_;
    my $sqlite = $this->{'sqlite'};

    $this->mac_exist($mac);

    my $sth = $sqlite->prepare( "SELECT Domain FROM dns WHERE mac = (?) and Domain = (?) " );
    $sth->execute($mac,$domain);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO dns(mac,Domain) VALUES (?,?)");
        $sth->execute($mac,$domain);
    }
}

sub stats_dhcp {
    my($this,$mac,$finger,$vendor_id,$computer_name,$hash,$detect) = @_;
    my $sqlite = $this->{'sqlite'};

    $this->mac_exist($mac);

    my $sth = $sqlite->prepare( "SELECT mac FROM dhcp WHERE mac = (?) and HASH =(?)" );
    $sth->execute($mac,$hash);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO dhcp(mac,Finger,Vendor_ID,Computer_name,HASH,Detect) VALUES (?,?,?,?,?,?)");
        $sth->execute($mac,$finger,$vendor_id,$computer_name,$hash,$detect);
    }
}

sub stats_http {
    my($this,$mac,$url,$user_agent,$headers) = @_;
    my $sqlite = $this->{'sqlite'};

    $this->mac_exist($mac);

    my $sth = $sqlite->prepare( "SELECT mac FROM http WHERE mac = (?) and URL = (?) and UA = (?) and UAPROF =(?)" );
    $sth->execute($mac,$url,$user_agent,$headers);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO http(mac,URL,UA,UAPROF) VALUES (?,?,?,?)");
        $sth->execute($mac,$url,$user_agent,$headers);
    }
}


sub mac_exist {
    my($this,$mac) = @_;

    my $vendor = oui_to_vendor($mac);
    my $sqlite = $this->{'sqlite'};    
    my $sth = $sqlite->prepare( "SELECT mac FROM mac WHERE mac = (?)" );
    $sth->execute($mac);

    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO mac(mac,Vendor) VALUES (?,?)");
        $sth->execute($mac,$vendor);
    }
}  

sub stats_disconnect {
    my($this) = @_;
    my $sqlite = $this->{'sqlite'};
    $sqlite->disconnect();
}

sub create_tables {
    my($this) = @_;

    my $sqlite = $this->{'sqlite'};

    $sqlite->do("DROP TABLE IF EXISTS mac");
    $sqlite->do("CREATE TABLE mac(mac TEXT PRIMARY KEY, Vendor TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dhcp");
    $sqlite->do("CREATE TABLE dhcp(Id INTEGER PRIMARY KEY AUTOINCREMENT,mac TEXT, Finger TEXT, Vendor_ID TEXT, Computer_name TEXT, HASH TEXT, Detect TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dns");
    $sqlite->do("CREATE TABLE dns(Id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT , Domain TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS http");
    $sqlite->do("CREATE TABLE http(Id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, URL TEXT, UA TEXT, UAPROF TEXT)");
    $sqlite->do("VACUUM");
}

sub export_dhcp_fingerprint {
    my ($this,$sql) = @_;

    my $sqlite = $this->{'sqlite'};
    my $sth = $sqlite->prepare($sql);
    
    $sth->execute;

    open FILE, ">>", "dhcp_finger.csv" or die $!;

    my $row;
 
    while ($row = $sth->fetchrow_arrayref()) {
        print FILE join("|",@$row)."\n";
    }

}

1;

