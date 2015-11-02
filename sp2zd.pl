#!/usr/bin/perl
#!C:\strawberry\perl\bin\perl

################################################################################
# Written by: Ernest G. Wilson II
# Email: ErnestGWilsonII@gmail.com
# Version 1.0
# Date: 2015-11-02
#
######################
# Installation Notes #
######################
#
#
################################################################################

################################################################################
# PERL Modules
use strict;			# PERL Best Practices
use warnings;		# PERL Best Practices
use DateTime;
use Net::Address::IP::Local;
use Sys::Hostname;
use LWP::UserAgent;
use JSON;
use MIME::Base64;
use URI::Escape;
use HTTP::Request::Common;
use File::Slurp;
################################################################################

################################################################################
# Global Variables
##################
# Declare variables
my $DEBUG = "0";
my $credentials = encode_base64('YourZDUsernam@domain.com:YourZDPassword');
# Read in the command line variables passed to us by SmokePing
my ($name_of_alert,$target,$loss_pattern,$rtt_pattern,$hostname,$raise) = @ARGV;
# Determine if edge trigger from SmokePing is an ALERT or CLEAR
if ( $ARGV[5] ) { $raise = "1"; } else { $raise = "0"; }
my $Status;
if ( "1" == $raise ) { $Status = "ALERT"; } else { $Status = "CLEAR"; }
my $Date = DateTime->now(@_);   # Get the current date/time for logging
my $Source;
my $LocalHostname = hostname;
my ($Site) = substr($LocalHostname, 0, 3);  # Get the first 3 letters of localhost
$Site = uc($Site);  # Convert to UPPER CASE
#print " $Site\n";
my $Subject;
$Source = Net::Address::IP::Local->public_ipv4;
#print "$Source\n";
$Subject = "SmokePing $name_of_alert from $Site $Source to $hostname $target";
my $TicketExists;
my $Ticket;
my $mtrReportFile;
my $Token;
my $OperationsURL = "https://ctl243.sharepoint.com/Operations/_layouts/15/start.aspx#/";
my $ProcessingSmokepingAlertsURL = "https://support.ctl.io/hc/en-us/articles/205518685-Processing-Smokeping-Alerts";
my $ContactingISPURL = "https://support.ctl.io/hc/en-us/articles/204246669-Contacting-ISP";
################################################################################

################################################################################
# Subroutines (called later during logic section)
#################################################

########################
# CREATE MTR REPORT FILE
sub CreateMTRReportFile
{
# Logging
my $sp2zdlogfile = "/tmp/sp2zd.log";
open(my $fh, '>>', $sp2zdlogfile);
print $fh "################################################################################\n";
print $fh "       Subject: $Subject\n";
print $fh "          Date: $Date\n";
print $fh "        Source: $Source \($Site SmokePing\)\n";
print $fh "      hostname: $hostname\n";
print $fh "         raise: $raise \($Status\)\n";
print $fh "        target: $target\n";
print $fh " name_of_alert: $name_of_alert\n";
print $fh "  loss_pattern: $loss_pattern\n";
print $fh "   rtt_pattern: $rtt_pattern\n";
print $fh "################################################################################\n";
close $fh;

my $dir = "/tmp/";
my $ReportPrefix = "SmokePing-report";
my $extension = ".txt";
$mtrReportFile = "$dir$ReportPrefix\_$Status\_$Site\-$Source\-to\-$hostname$extension";
if ( $DEBUG == 1 ) { print " mtrReportFile is $mtrReportFile\n"; }

if ( -e ($mtrReportFile) ) { unlink ($mtrReportFile); }

my $cmd = "/usr/bin/mtr --report --report-wide -c 10 --show-ips --aslookup $hostname >> $mtrReportFile";
system($cmd);

$cmd = "/usr/bin/unix2dos -q $mtrReportFile";
system($cmd);
}

########################
# UPLOAD MTR REPORT FILE
sub UploadReportFile
{
my $file = $mtrReportFile;

# Set the request parameters
my $url = "https://t3n.zendesk.com/api/v2/uploads.json?filename=$file";

# Create the user agent and make the request
my $ua = LWP::UserAgent->new(ssl_opts =>{ verify_hostname => 0 });
my $response = $ua->post($url,
                        'Content-Type'  => 'multipart/form-data',
                        'Authorization' => "Basic $credentials",
                        'Content'       => [ 'mtr' => [ $file, $file, 'text/plain'] ]
                        );

# Check for HTTP errors
die 'http status: ' . $response->code . '  ' . $response->message
    unless ($response->is_success);
    
if ( $DEBUG == 1 ) { print " JSON returned was:\n"; }
if ( $DEBUG == 1 ) { print $response->content; } # All output 
# Get the token value of the file that was uploaded
my $data = decode_json($response->content);
my $results = $data->{'upload'};
$Token = $results->{"token"};
if ( $DEBUG == 1 ) { print " Token is: $Token\n"; }
}

###############################
# SEARCH FOR AN EXISTING TICKET
sub SearchForExistingTicket
{
my $search = "subject:$Subject via:api status<solved";

my %params = (
    query => $search,
);

my $url = URI->new('https://t3n.zendesk.com/api/v2/search.json');
$url->query_form(%params);

my $ua = LWP::UserAgent->new(ssl_opts =>{ verify_hostname => 0 });
my $response = $ua->get($url, 'Authorization' => "Basic $credentials");
die 'Status: ' . $response->code . '  ' . $response->message
    unless ($response->is_success);

# Get the ticket info
my $data = decode_json($response->content);
my @results = @{ $data->{'results'} };
foreach my $result ( @results ) {
    # print $result->{"subject"} . "\n";
    # print $result->{"id"} . "\n";
    $Ticket = $result->{"id"};
}
if ( $Ticket ) { $Ticket = $Ticket } else { $Ticket = "0"; }
if ( $Ticket == "0" ) { $TicketExists = 0; } else { $TicketExists = 1; }
if ( $DEBUG == 1 ) { print " Existing Ticket number is $Ticket\n"; }
if ( $DEBUG == 1 ) { print " TicketExists is $TicketExists\n"; }
}

#############################
# CREATE A NEW ZENDESK TICKET
sub CreateNewTicket
{
if ( $DEBUG == 1 ) { print " Create a new ticket needed!\n"; }

# Create the text for the comment in ZenDesk
my $body = "Status: $Status\n
Subject: $Subject\n
SmokePing URL: http://$Source/smokeping/smokeping.cgi?target=$target\n
You may also investigate further by logging into the SmokePing server in $Site
ssh $Source
mtr --show-ips --aslookup $hostname\n
REF KBs:
Processing SmokePing Alerts: $ProcessingSmokepingAlertsURL
SharePoint Operations ISP Listing: $OperationsURL
Contacting ISP: $ContactingISPURL\n
SmokePing said:
name_of_alert: $name_of_alert
target: $target
loss_pattern: $loss_pattern
rtt_pattern: $rtt_pattern
hostname: $hostname
raise: $raise\n";

# New ticket info
my $group_id =  '20048861';
my $ticket_form_id = '65609';
my $type = 'incident';
my $priority = 'normal';
my $ticket_service_type_id = '21619801';
my $ticket_service_type_value = 'problem';
my $ticket_account_alias_id = '20321291';
my $ticket_account_alias_value = 'T3N';
my $ticket_impacted_product_id = '24305619';
my $ticket_impacted_product_value = 'single__network';

# Package the data in a data structure matching the expected JSON
my %data = (
    ticket => {
       group_id => $group_id,
        subject => $Subject,
 ticket_form_id => $ticket_form_id,
           type => $type,
       priority => $priority,
  custom_fields => [
                   {
                   id => $ticket_service_type_id,
                   value => $ticket_service_type_value
                   },
                   {
                   id => $ticket_account_alias_id,
                   value => $ticket_account_alias_value
                   },
                   {
                   id => $ticket_impacted_product_id,
                   value => $ticket_impacted_product_value
                   },
                   ],
        comment => {
                   body => $body,
                   },
           },
);

# Encode the data structure to JSON
my $data = encode_json(\%data);

# Set the request parameters
my $url = 'https://t3n.zendesk.com/api/v2/tickets.json';
my $credentials = encode_base64('ernest.wilson@ctl.io:Z3nD3skSucks!');

# Create the user agent and make the request
my $ua = LWP::UserAgent->new(ssl_opts =>{ verify_hostname => 0 });
my $response = $ua->post($url,
                         'Content' => $data,
                         'Content-Type' => 'application/json',
                         'Authorization' => "Basic $credentials");

# Check for HTTP errors
die 'http status: ' . $response->code . '  ' . $response->message
    unless ($response->is_success);
	
# Get the ticket info
$data = decode_json($response->content);
my $results = $data->{'ticket'};
$Ticket = $results->{"id"};

if ( $DEBUG == 1 ) { print " Successfully created new ticket: $Ticket\n"; }
}

###################################
# UPDATE AN EXISTING ZENDESK TICKET
sub UpdateExistingTicket
{
# Ticket to update
my $public = 'false';

# Create the comment for the body in Zendesk
my $body = "Status: $Status\n
Please see attached mtr report for details";

# Package the data in a hash matching the expected JSON
my %data = (
    ticket => {
        comment => {
          public => $public,
            body => $body,
            uploads => [$Token],
        },
    },
);

# Convert the hash to JSON
my $data = encode_json(\%data);

# Set the request parameters
my $url = "https://t3n.zendesk.com/api/v2/tickets/$Ticket.json";

# Create the user agent and make the request
my $ua = LWP::UserAgent->new(ssl_opts =>{ verify_hostname => 0 });
my $response = $ua->put($url,
                        'Content' => $data,
                        'Content-Type' => 'application/json',
                        'Authorization' => "Basic $credentials");

# Check for HTTP errors
die 'http status: ' . $response->code . '  ' . $response->message
    unless ($response->is_success);

# Report success
if ( $DEBUG == 1 ) { print " Successfully updated existing ticket: $Ticket\n"; }
}
################################################################################

################################################################################
# Program Logic
###############
&CreateMTRReportFile;		# Runs an mtr and creates mtr report file
&UploadReportFile;			# Uploads mtr report file to ZD and gets a token
&SearchForExistingTicket;	# Search ZD for an existing ticket
if ( $TicketExists == "1")
	{
	UpdateExistingTicket;	# Adds internal comment and attaches the mtr report
	}
	else
	{
	CreateNewTicket;		# Creates a new ZD ticket with a public comment
	if ( $Ticket >= "1")
	   {
	   UpdateExistingTicket;	# Adds internal comment and attaches the mtr report
	   }
	}
################################################################################
exit 0;	# Exit cleanly