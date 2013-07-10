#!/usr/bin/perl

# ----------------------------------------------------------------------
# ActiveDNS
# Copyright (C) 2013, Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------

use strict;
use warnings;
use POSIX qw(setsid strftime);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use Net::DNS::Async;
use Net::DNS::Packet;
use Time::HiRes qw(usleep);
use Switch;
#use Data::Dumper;

=head1 NAME

 activedns.pl - Active resolve Domains.

=head1 VERSION

0.22

=head1 SYNOPSIS

 $ activedns.pl [options]

 OPTIONS:

 --file <file>          : the file to load domains from (default /etc/activedns/domains.txt)
 --log <file>           : the file to log dns results in (default /var/log/activedns.log)
 --nolog                : turn off logging to --log <file> (default on)
 --batch                : run through all domains once then exit
 --usleep               : sleep in microseconds between each request (default 100000 ms)
 --ttl-min              : minimum TTL for a domain before we query again (default 60)
 --ttl-mul              : TTL multiplier to extend the time between queries (default 1)
 --persistance          : will try to load query state on startup, and flush state when exiting (default 1)
 --persfile             : the file to load and save persistance from (default /var/lib/activedns/activedns-state.log)
 --daemon               : enables daemon mode
 --verbose              : enables some verboseness
 --debug <int>          : enable debug messages (default: 0 (disabled))
 --help                 : this help message
 --version              : show version

=cut

my $VERSION       = 0.22;
my $DEBUG         = 0;
my $VERBOSE       = 0;
my $DAEMON        = 0;
my $TIMEOUT       = 1;
my $BATCH         = 0;
my $SLEEP         = 100000;
my $TTL_MUL       = 1;
my $TTL_MIN       = 180;
my $dkey          = {};
my $LIP           = q(192.168.0.1);
my $NOLOG         = 0;
my $PERSISTANCE   = 1;
my $PERSFILE      = q(/var/lib/activedns/activedns-state.log);
my $ADNSFILE      = q(/etc/activedns/domains.txt);
my $ADNSLOG       = q(/var/log/activedns.log);
my $LOGFILE       = q(/var/log/activedns-run.log);
my $PIDFILE       = q(/var/run/activedns.pid);

GetOptions(
   'file=s'        => \$ADNSFILE,
   'batch'         => \$BATCH,
   'ttl-mul=s'     => \$TTL_MUL,
   'ttl-min=s'     => \$TTL_MIN,
   'nolog'         => \$NOLOG,
   'persistance=s' => \$PERSISTANCE,
   'persfile=s'    => \$PERSFILE,
   'debug=s'       => \$DEBUG,
   'daemon'        => \$DAEMON,
   'verbose'       => \$VERBOSE,
);

# Dont multiply with 0 etc!
$TTL_MUL = 1 if ( $TTL_MUL < 1 );
# Set a saine minimum default...
$TTL_MIN = 60 if ( $TTL_MUL < 60 );

# Signal handlers
use vars qw(%sources);
$SIG{"HUP"}   = sub { reload_domain_file() };
$SIG{"INT"}   = sub { gameover() };
$SIG{"TERM"}  = sub { gameover() };
$SIG{"QUIT"}  = sub { gameover() };
$SIG{"KILL"}  = sub { gameover() };
#$SIG{"ALRM"}  = sub { print_stats(); alarm $TIMEOUT; };

logger("[*] Starting...\n");

my @domains = load_domain_list($ADNSFILE);

my $LFH;
if ( $ADNSLOG ne "" ) {
  open($LFH, ">>", $ADNSLOG) or die "[E] Could not open '$ADNSLOG': $!";
}

$dkey = load_persistance($PERSFILE) if ($PERSISTANCE != 0);

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   logger("[*] Daemonizing...\n");
   chdir ("/") or die "chdir /: $!\n";
   open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
   open (STDOUT, "> $LOGFILE") or die "open > $LOGFILE: $!\n";
   defined (my $dpid = fork) or die "fork: $!\n";
   if ($dpid) {
      # Write PID file
      open (PID, "> $PIDFILE") or die "open($PIDFILE): $!\n";
      print PID $dpid, "\n";
      close (PID);
      exit 0;
   }
   setsid ();
   open (STDERR, ">&STDOUT");
}

# Run for ever....
while (1) {
  my $a_res  = new Net::DNS::Async(QueueSize => 10, Retries => 3, Timeout => 3);
  foreach my $domain (@domains) {
    my $epoch = time;
    $domain = lc($domain);
    if (not defined $dkey->{$domain}) {
      $dkey->{$domain} = 0;
    }

    if ($dkey->{$domain} <= $epoch) {
      logger("[D] Processing domain: $domain\n") if $DEBUG;
      my $packet = new Net::DNS::Packet($domain);
      $a_res->add({ Nameservers => [ qw(8.8.8.8 8.8.4.4) ],
                    Callback    => \&callback,
                    Query       => [ $packet ]
                  });
    } else {
      my $tleft = $dkey->{$domain} - $epoch;
      logger("[D] Time left for recheck of $domain : $tleft\n") if $DEBUG;
    }
    usleep($SLEEP);
  }
  $a_res->await();
  sleep 5;
  logger("[D] Looping\n") if $DEBUG;
}

=head1 FUNCTIONS

=head2 load_domain_list

 Callback rutine for the DNS response.

=cut

sub callback {
  my $packet = shift;
  my $query = q();
  my $rr = q();
  my $type = q();
  my $answer = q();
  my $ttl = q();
  my $epoch = time;
  my $serverip = q();

  if ( defined($packet) ) {
    $serverip = $packet->answerfrom;
    if ( $packet->header->rcode eq "NOERROR") {
        #print Dumper $packet;
      foreach my $r ( $packet->answer ) {
        #print Dumper $r;
        $query = lc($r->name);
        $rr    = $r->class;
        $type  = $r->type;
        switch ($type) {
          case /^(A|AAAA)/ {
            $answer= $r->address;
          }
          case "CNAME" {
            $answer= $r->cname;
          }
        }
        $ttl = $r->ttl;
        $ttl = $TTL_MIN if ($ttl < $TTL_MIN);
        $dkey->{$query} = $epoch + ($ttl * $TTL_MUL);
        log_adns($epoch, $serverip, $rr, $query, $type, $answer, $r->ttl);
      }
    } else {
      my @question = $packet->question;
      $query = lc($question[0]->qname);
      $rr    = $question[0]->qclass;
      $type  = $question[0]->qtype;
      $answer= $packet->header->rcode;
      $ttl   = 43200;
      $dkey->{$query} = $epoch + ($ttl * $TTL_MUL);
      log_adns($epoch, $serverip, $rr, $query, $type, $answer, $ttl);
    }
  }
}

=head2 reload_domain_file

 Reloads the domain file.

=cut

sub reload_domain_file {
  my $bcnt = @domains;
  @domains = ();
  @domains = load_domain_list($ADNSFILE);
  my $acnt = @domains;
  my $ncnt = ($acnt - $bcnt);
  if ( $ncnt == 0 ) {
    logger("[*] Reload of domain file: No new domains\n");
  } elsif ( $ncnt > 0 ) {
    logger("[*] Reload of domain file: $ncnt new domains\n");
  } else {
    logger("[*] Reload of domain file: ". abs($ncnt)." less domains\n");
  }
}

=head2 log_adns

 logs dns answers in PassiveDNS style...

=cut

sub log_adns {
  my($epoch, $serverip, $rr, $query, $type, $answer, $ttl) = @_;
  my $count = 1;
  return if not defined $LFH;

  if ( ($NOLOG == 0) && ($ADNSLOG ne "") ) {
    print $LFH "$epoch.123456||$LIP||$serverip||$rr||$query||$type||$answer||$ttl||$count\n";
  }

  if ( $DAEMON == 0 && $VERBOSE == 1) {
    logger("[*] $epoch.123456||$LIP||$serverip||$rr||$query||$type||$answer||$ttl||$count\n");
  }
}

=head2 load_domain_list

 Reads a file and pushes domains into an array.
 Input $file - Output @domains

=cut

sub load_domain_list {
    my $file = shift;
    my @domain = ();
    my $cnt = 0;

    open(my $FH, "<", $file) or die "[E] Could not open '$file': $!";

    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        $line =~ s/\t//g;
        $line =~ s/ //g;
        next LINE unless($line); # empty line
        # One should check for a more or less sane domaine.

        logger("[D] $line\n") if $DEBUG > 3;
        push(@domains, $line);
        $cnt++;
    }
    if ($cnt > 1) {
      logger("[*] Loaded $cnt domains from file: $file\n") if $VERBOSE;
    } else {
      logger("[*] Loaded $cnt domain from file: $file\n") if $VERBOSE;
    }
    return @domains;
}

=head2 logger

 Adds time prefix to logg output. Takes $msg as input.

=cut

sub logger {
  my $msg = shift;
  print strftime('%F %H:%M:%S', localtime), " $msg";
}

=head2 load_persistance

 Loads query state from a saved persistance file

=cut

sub load_persistance {
  my $file = shift;
  my $cnt = 0;
  my $key = {};
  if ( $PERSISTANCE != 0 ) {
    open(my $FH, "<", $file) or die "[E] Could not open '$file': $!";
    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        $line =~ s/\t//g;
        $line =~ s/ //g;
        next LINE unless($line); # empty line
        logger("[D] $line\n") if $DEBUG > 3;
        my ($domain,$epoch) = split(/,/,$line);
        $key->{$domain} = $epoch;
        $cnt++;
    }
  }
  logger("[*] Loaded $cnt enteries from persistance: $file\n") if $VERBOSE;
  return $key;
}

=head2 save_persistance

 Saves the domain hash to a persistance file

=cut

sub save_persistance {
  my $hash = shift;
  my $cnt = 0;

  if ( $PERSISTANCE != 0 ) {
    if (open(my $PFH, ">", $PERSFILE)) {
      for my $domain ( keys %{$hash} ) {
        my $epoch = $hash->{$domain};
        print $PFH "$domain,$epoch\n";
        $cnt++;
      }
    } else {
      logger("[E] Could not open '$PERSFILE': $!");
    }
  }
  logger("[*] Saved $cnt entries to persistance: $PERSFILE\n") if $VERBOSE;
}

=head2 gameover

 Terminates the program in a sainfull way.

=cut

sub gameover {
  save_persistance($dkey) if ($PERSISTANCE != 0);
  unlink ($PIDFILE) if $DAEMON;
  logger("[*] Terminating...\n");
  exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

 Copyright (C) 2013, Edward Fjellskål <edwardfjellskaal@gmail.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut
