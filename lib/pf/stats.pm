package pf::stats;

use strict;
use DBI;
use Readonly;

use pf::util qw(oui_to_vendor);
use pf::config;

Readonly::Scalar our $DATABASE                => "$var_dir/result.db";

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

    my $sth = $sqlite->prepare( "SELECT Domain FROM dns WHERE mac = (?) and domain = (?) " );
    $sth->execute($mac,$domain);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO dns(mac,domain) VALUES (?,?)");
        $sth->execute($mac,$domain);
    }
}

sub stats_dhcp {
    my($this,$mac,$finger,$vendor_id,$computer_name,$hash,$detect) = @_;
    my $sqlite = $this->{'sqlite'};

    $this->mac_exist($mac);

    my $sth = $sqlite->prepare( "SELECT mac FROM dhcp WHERE mac = (?) and hash =(?)" );
    $sth->execute($mac,$hash);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO dhcp(mac,finger,vendor_id,computer_name,hash,detect) VALUES (?,?,?,?,?,?)");
        $sth->execute($mac,$finger,$vendor_id,$computer_name,$hash,$detect);
    }
}

sub stats_http {
    my($this,$mac,$hash,$user_agent,$headers,$suites) = @_;
    my $sqlite = $this->{'sqlite'};

    $this->mac_exist($mac);

    my $sth = $sqlite->prepare( "SELECT mac FROM http WHERE mac = (?) and hash = (?)" );
    $sth->execute($mac,$hash);
    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO http(mac,hash,user_agent,uaprof,suites) VALUES (?,?,?,?,?)");
        $sth->execute($mac,$hash,$user_agent,$headers,$suites);
    }
}


sub mac_exist {
    my($this,$mac) = @_;

    my $vendor = oui_to_vendor($mac);
    my $sqlite = $this->{'sqlite'};    
    my $sth = $sqlite->prepare( "SELECT mac FROM mac WHERE mac = (?)" );
    $sth->execute($mac);

    if (!$sth->fetchrow()) {
        $sth = $sqlite->prepare( "INSERT INTO mac(mac,vendor) VALUES (?,?)");
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
    $sqlite->do("CREATE TABLE mac(mac TEXT PRIMARY KEY, vendor TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dhcp");
    $sqlite->do("CREATE TABLE dhcp(id INTEGER PRIMARY KEY AUTOINCREMENT,mac TEXT, finger TEXT, vendor_id TEXT, computer_name TEXT, hash TEXT, detect TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dns");
    $sqlite->do("CREATE TABLE dns(id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT , domain TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS http");
    $sqlite->do("CREATE TABLE http(id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, hash TEXT, user_agent TEXT, uaprof TEXT, suites TEXT)");
    $sqlite->do("VACUUM");
}

sub export_dhcp_fingerprint {
    my ($this,$sql) = @_;

    my $sqlite = $this->{'sqlite'};
    my $sth = $sqlite->prepare($sql);
    
    $sth->execute;

    open FILE, ">>", "$var_dir/dhcp_finger.csv" or die $!;

    my $row;
 
    while ($row = $sth->fetchrow_arrayref()) {
        print FILE join("|",@$row)."\n";
    }

}

1;

