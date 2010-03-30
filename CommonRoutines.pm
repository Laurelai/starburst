#!/usr/bin/perl -w
use strict;
package CommonRoutines;

our @EXPORT = qw[
registry_init_from_file
registry_read
registry_write
registry_delete
registry_deletetree
plugin_load
plugin_unload
plugin_reload
debug
registry_tree_single
registry_pretty_print
registry_pretty_print_int
registry_pretty_print_recurse_errors
registry_size

gen_salt
gen_hash

seconds_lenstr
format_bytes
];

use Exporter;
use Azusa::Configuration;
use POSIX  qw[strftime];
our @ISA = qw[Exporter];
our %registry;
our $error;

sub registry_init_from_file {
	my ($file) = @_;
	if (!$file) {
		$error = 'No file specified';
		return(0);
	}
	my ($fh, %temp);
	my $confreader = Azusa::Configuration->new();
	my ($lp, $err) = $confreader->load($file, \%temp);
	if (!$lp) {
		$error = $err;
		return(0);
	}
	my ($key, $val);
	foreach $key (sort(keys(%temp))) {
		$val = $temp{$key};
		registry_write($key, $val);
	}
	return(1);
}

sub registry_read  {
	my ($key)  = @_;
	my ($data, $exist, $realkey);
	my $buffer = $key;
	$buffer    =~ s/(\w+)\.?/{$1}/g;
	$realkey   = '$exist = $registry'.$buffer.';';
	$buffer    = '$data = $registry'.$buffer.'{value}';
	eval($realkey);
	if (!$exist) {
		debug('Attempt to read non-existent key '.$key, 2);
		return(0);
	}
	eval($buffer);
	if ($@) {
		print "Internal error in registry_read. Please report this bug.\n";
		print "failed buffer: ".$buffer." reason:\n";
		print $@."\n\n";
		return(0);
	}
	return($data);
}


sub registry_write {
	my ($key, $val) = @_;
	debug('writing registry key '.$key.': "'.$val.'"', 3);
	my $buffer = $key;
	$buffer    =~ s/(\w+)\.?/{$1}/g;
	$buffer    = '$registry'.$buffer.'{value} = $val;';
	eval($buffer);
	if ($@) {
		print "Internal error in registry_write. Please report this bug.\n";
		print "failed buffer: \n".$buffer."\n reason:\n";
		print $@."\n\n";
		return(0);
	}
	return(1);
}

sub registry_delete {
	my ($key)  = @_;
	my $buffer = $key;
	$buffer    =~ s/(\w+)\.?/{$1}/g;
	$buffer    = 'undef($registry'.$buffer.'{value});';
	eval($buffer);
	if ($@) {
		print "Internal error in registry_delete. Please report this bug.\n";
		print "failed buffer: ".$buffer." reason:\n";
		print $@."\n\n";
		return();
	}
	return(1);
}

sub registry_deletetree {
	my ($key)  = @_;
	my $buffer = $key;
	$buffer    =~ s/(\w+)\.?/{$1}/g;
	$buffer    = 'undef($registry'.$buffer.');';
	eval($buffer);
	if ($@) {
		print "Internal error in registry_deletetree. Please report this bug.\n";
		print "failed buffer: ".$buffer." reason:\n";
		print $@."\n\n";
		return();
	}
	return(1);
}

sub plugin_load    {
	my ($plugin_name) = @_;
	my $realname      = $plugin_name;
	$plugin_name      =~ s!\.!/!g;
	$plugin_name     .= '.plg';
	$plugin_name      = registry_read('plugins.folder').$plugin_name;
	debug('Plugin location: '.$plugin_name,   3);
	my ($fh, $error);
	open($fh, '<', $plugin_name) or $error = $!;
	my @temp = <$fh>;
	close($fh);
	my $temp = join('', @temp);
	my ($__plugin_name, $__plugin_author, $__plugin_date, $__plugin_version, $__plugin_handle);
	eval($temp);
	$error = $@ if ($@);
	$error = 'Incomplete module header' if (!$error && (!$__plugin_name || !$__plugin_author || !$__plugin_date || !$__plugin_version || !$__plugin_handle));
	if ($error) {
		debug('Failed to load '.$realname.' - enable verbosity for error messages');
		debug($realname.' - '.$error, 1);
		return(0);
	}
	debug('Successfully loaded plugin \''.$__plugin_name.'\' v'.$__plugin_version.' ('.$__plugin_author.' / '.$__plugin_date.')', 0);
	$__plugin_handle->initialize();
	registry_write('plugins.loaded.'.$realname.'.handle',  $__plugin_handle);
	registry_write('plugins.loaded.'.$realname.'.name',    $__plugin_name);
	registry_write('plugins.loaded.'.$realname.'.author',  $__plugin_author);
	registry_write('plugins.loaded.'.$realname.'.date',    $__plugin_date);
	registry_write('plugins.loaded.'.$realname.'.version', $__plugin_version);
	registry_write('plugins.loaded.'.$realname.'.time',    time);
	my $conv_realname = $realname; $conv_realname =~ s/\./___/g;
	registry_write('plugins.list.'.$conv_realname, 1);
	return(1);
}

sub plugin_unload {
	my ($plugin_name) = @_;
	return if (!registry_read('plugins.loaded.'.$plugin_name.'.handle'));
	no warnings 'redefine'; # this is kinda messy. sometimes redefines.
	debug('Unloading plugin '.$plugin_name.'.', 0);
	registry_read('plugins.loaded.'.$plugin_name.'.handle')->shutdown();
	my $conv_realname = $plugin_name; $conv_realname =~ s/\./___/g;
	registry_deletetree('plugins.loaded.'.$plugin_name);
	registry_delete('plugins.list.'.$conv_realname);
}

sub plugin_reload {
	my ($plugin_name) = @_;
	plugin_unload($plugin_name);
	plugin_load($plugin_name);
}



sub debug {
	my ($message, $verbosity) = @_;
	my $call_level = 1;
	my $regverb = $registry{verbosity}{value} || 0;
	if ($regverb >= $verbosity) {
               	my( $package, $filename, $line, $subroutine ) = caller($call_level);
               	while ($filename =~ /^\(eval \d+\)$/) { # we're in an eval. go up one
			( $package, $filename, $line, $subroutine ) = caller($call_level++);
		}
               	$subroutine                                   = "main::main" if( !$subroutine );
               	$filename                                     = $0 if( !$filename );
		my $debugmsg = '(debug) '.( split( /::/, $subroutine ) )[-1].'@'.$filename.' - ';
               	$message                                      = ($verbosity > 2 ? $debugmsg : '['.strftime("%a %b %e %H:%M:%S %Y", localtime).'] ').$message."\n";
               	print $message;
       	}
       	return( undef );
}

sub registry_tree_single {
	my ($branch) = @_;
	my $reference;
	my $buffer = $branch;
	$buffer    =~ s/(\w+)\.?/{$1}/g;
	$buffer    = '$reference = $registry'.$buffer.';';
	eval($buffer);
	my (@nodes);
	foreach my $leaf (sort(keys(%$reference))) {
		push(@nodes, $leaf);
	}
	return(@nodes);
}

sub gen_salt { # AP hash based on input that is encoded and pseudo-hashed again to give 32 byte output
	my ($password, $revflag) = @_;
	my ($salt, @chars, $hash);
	@chars = split(//, $password);
	@chars = reverse(@chars) if ($revflag);
	$salt = 0;
	my $i = 0;
	foreach my $char (@chars) {
		$i++;
		# simple AP hash
		$salt ^= (($i & 1) == 0) ? ( ($salt << 7) ^ ord($char) ^ ($salt >> 3) ) : (~(($salt << 11) ^ ord($char) ^ ($salt >> 5)));

	}
#	printf("genkey %s\n", $salt);
	srand($salt);
	$salt  = rand(65536);
	$salt .= int(rand(9)) while (length($salt) < 18);
	$salt  =~ s/\.//g;
#	printf("parthash: %x revflag: %d\n", $salt, $revflag);
	return($salt) if ($revflag);
	$salt .= gen_salt($password, 1);
	$salt  = substr($salt, 0, 32);
	@chars = split(//, $salt);
	undef($salt);
	for (my $x = 0; $x < 32; $x += 2) {
		$salt .= sprintf('%02x', $chars[$x].$chars[$x+1]);
	}
	return($salt);
}

sub gen_hash {
	my ($password) = @_;
	my $md5        = MD5->new;
	$md5->add(gen_salt($password));
	$md5->add($password);
	return($md5->hexdigest);
}

sub seconds_lenstr { 
	my ($seconds) = @_;
	my @parts = gmtime($seconds);
	my ($str);
	$str .= sprintf("%d days, ",    $parts[7]) if ($parts[7]);
	$str .= sprintf("%d hours, ",   $parts[2]) if ($parts[2]);
	$str .= sprintf("%d minutes, ", $parts[1]) if ($parts[1]);
	$str .= sprintf("%d seconds",   $parts[0]) if ($parts[0]);
	return($str);
}

sub format_bytes { 
	my ($bytes) = @_;
	return(Number::Bytes::Human::format_bytes($bytes));
}
	

sub registry_size {
	return(keys(%registry));
}

sub registry_pretty_print { registry_pretty_print_int(\%CommonRoutines::registry); }

# The following was kindly stolen from a google search
#------------------------------------------------------------------
sub registry_pretty_print_int {
    my $hash = shift;
    my ($space, $newline, $delimiter) = @_;
    $space = "" unless (defined $space);
    $newline = "\n\n\n" unless (defined $newline);
    $delimiter = "\n--------------------------------------------" unless (defined $delimiter);
    my $str = "";

    for (sort keys %{$hash}) {
        my $value = $hash->{$_};
        $str .= "$newline$space$_ == $value$delimiter";
        $str .= registry_pretty_print_recurse_errors($value,$space);
    }
    return($str);
}

#------------------------------------------------------------------
sub registry_pretty_print_recurse_errors {
    my $str;
    my ($value,$space) = @_;
    my $ref = ref $value;

    if ($ref eq 'ARRAY') {
        my $i = 0;
        my $isEmpty = 1;
        my @array = @$value;
        $space .= "    ";
        for my $a (@array) {
            if (defined $a) {
                $isEmpty = 0;
                $str .= "\n$space$_\[$i\] :";
                $str .= registry_pretty_print_recurse_errors($a,$space);
            }
            $i++;
        }
        $str .= "= { }" if ($isEmpty);

    } elsif ($ref eq 'HASH') {
        $space .= "    ";
        for my $k (sort keys %$value) {
            if ( ( ref($value->{$k}) eq 'HASH') || (ref $value->{$k} eq 'ARRAY') ) {
                my $val = $value->{$k};
                $str .= "\n\n$space$k";
            }
            else {
                $str .= "\n$space$k == ";
            }
            $str .= registry_pretty_print_recurse_errors($value->{$k},$space);
      }

      # we have reached a scalar (leaf)
    } elsif ($ref eq '') {
        $str .= "$value";
    }
$str
}

package Number::Bytes::Human;

use strict;
use warnings;

our $VERSION = '0.07';

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(format_bytes);

require POSIX;
use Carp qw(croak carp);

#my $DEFAULT_BLOCK = 1024;
#my $DEFAULT_ZERO = '0';
#my $DEFAULT_ROUND_STYLE = 'ceil';
my %DEFAULT_SUFFIXES = (
  1024 => ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'],
  1000 => ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'],
  1024000 => ['', 'M', 'T', 'E', 'Y'],
  si_1024 => ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'],
  si_1000 => ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'],
);
my @DEFAULT_PREFIXES = @{$DEFAULT_SUFFIXES{1024}};

sub _default_suffixes {
  my $set = shift || 1024;
  if (exists $DEFAULT_SUFFIXES{$set}) {
    return @{$DEFAULT_SUFFIXES{$set}} if wantarray;
    return [ @{$DEFAULT_SUFFIXES{$set}} ];
  }
  croak "unknown suffix set '$set'";
}

my %ROUND_FUNCTIONS = (
  ceil => \&POSIX::ceil,
  floor => \&POSIX::floor,
  #round => sub { shift }, # FIXME
  #trunc => sub { int shift } # FIXME

  # what about 'ceiling'?
);

sub _round_function {
  my $style = shift;
  if (exists $ROUND_FUNCTIONS{$style}) {
    return $ROUND_FUNCTIONS{$style}
  }
  croak "unknown round style '$style'";
}

sub _parse_args {
  my $seed = shift;
  my %args;

  my %options;
  unless (defined $seed) { # use defaults
    $options{BLOCK} = 1024;
    $options{ROUND_STYLE} = 'ceil';
    $options{ROUND_FUNCTION} = _round_function($options{ROUND_STYLE});
    $options{ZERO} = '0';
    #$options{SUFFIXES} = # deferred to the last minute when we know BLOCK, seek [**]
  } 
  # else { %options = %$seed } # this is set if @_!=0, down below

  if (@_==0) { # quick return for default values (no customized args)
    return (defined $seed) ? $seed : \%options;
  } elsif (@_==1 && ref $_[0]) { # \%args
    %args = %{$_[0]};
  } else { # arg1 => $val1, arg2 => $val2
    %args = @_;
  }

  # this is done here so this assignment/copy doesn't happen if @_==0
  %options = %$seed unless %options; 

# block | block_size | base | bs => 1024 | 1000
# block_1024 | base_1024 | 1024 => $true
# block_1000 | base_1000 | 1024 => $true
  if ($args{block} ||
      $args{block_size} ||
      $args{base} ||
      $args{bs}
    ) {
    my $block = $args{block} ||
                $args{block_size} ||
                $args{base} ||
                $args{bs};
    unless ($block==1000 || $block==1024 || $block==1_024_000) {
      croak "invalid base: $block (should be 1024, 1000 or 1024000)";
    }
    $options{BLOCK} = $block;
    
  } elsif ($args{block_1024} ||
           $args{base_1024}  ||
           $args{1024}) {

    $options{BLOCK} = 1024;
  } elsif ($args{block_1000} ||
           $args{base_1000}  ||
           $args{1000}) {

    $options{BLOCK} = 1000;
  }

# round_function => \&
# round_style => 'ceil' | 'floor' | 'round' | 'trunc'
  if ($args{round_function}) {
    unless (ref $args{round_function} eq 'CODE') {
      croak "round function ($args{round_function}) should be a code ref";
    }
    $options{ROUND_FUNCTION} = $args{round_function};
    $options{ROUND_STYLE} = $args{round_style} || 'unknown';
  } elsif ($args{round_style}) {
    $options{ROUND_FUNCTION} = _round_function($args{round_style});
    $options{ROUND_STYLE} = $args{round_style};
  }

# suffixes => 1024 | 1000 | si_1024 | si_1000 | 1024000 | \@
  if ($args{suffixes}) {
    if (ref $args{suffixes} eq 'ARRAY') {
      $options{SUFFIXES} = $args{suffixes};
    } elsif ($args{suffixes} =~ /^(si_)?(1000|1024)$/) {
      $options{SUFFIXES} = _default_suffixes($args{suffixes});
    } else {
      croak "suffixes ($args{suffixes}) should be 1024, 1000, si_1024, si_1000, 1024000 or an array ref";
    }
  } elsif ($args{si}) {
    my $set = ($options{BLOCK}==1024) ? 'si_1024' : 'si_1000';
    $options{SUFFIXES} = _default_suffixes($set);
  } elsif (defined $args{unit}) {
    my $suff = $args{unit};
    $options{SUFFIXES} = [ map  { "$_$suff" } @DEFAULT_PREFIXES ];
  }

# zero => undef | string
  if (exists $args{zero}) {
    $options{ZERO} = $args{zero};
    if (defined $options{ZERO}) {
      $options{ZERO} =~ s/%S/$options{SUFFIXES}->[0]/g 
    }
  }

# quiet => 1
  if ($args{quiet}) {
    $options{QUIET} = 1;
  }

  if (defined $seed) {
    %$seed = %options;
    return $seed;
  }
  return \%options
}

# NOTE. _format_bytes() SHOULD not change $options - NEVER.

sub _format_bytes {
  my $bytes = shift;
  return undef unless defined $bytes;
  my $options = shift;
  my %options = %$options;

  local *human_round = $options{ROUND_FUNCTION};

  return $options{ZERO} if ($bytes==0 && defined $options{ZERO});

  my $block = $options{BLOCK};

  # if a suffix set was not specified, pick a default [**]
  my @suffixes = $options{SUFFIXES} ? @{$options{SUFFIXES}} : _default_suffixes($block);

  # WHAT ABOUT NEGATIVE NUMBERS: -1K ?
  my $sign = '';
  if ($bytes<0) {
     $bytes = -$bytes;
     $sign = '-';
  }
  return $sign . human_round($bytes) . $suffixes[0] if $bytes<$block;

#  return "$sign$bytes" if $bytes<$block;

  my $x = $bytes;
  my $suffix;
  foreach (@suffixes) {
    $suffix = $_, last if human_round($x) < $block;
    $x /= $block;
  }
  unless (defined $suffix) { # number >= $block*($block**@suffixes) [>= 1E30, that's huge!]
      unless ($options{QUIET}) {
        my $pow = @suffixes+1; 
        carp "number too large (>= $block**$pow)"
      }
      $suffix = $suffixes[-1];
      $x *= $block;
  }
  # OPTION: return "Inf"

  my $num;
  if ($x < 10.0) {
    $num = sprintf("%.1f", human_round($x*10)/10); 
  } else {
    $num = sprintf("%d", human_round($x));
  }

  "$sign$num$suffix"

}

# convert byte count (file size) to human readable format
sub format_bytes {
  my $bytes = shift;
  my $options = _parse_args(undef, @_);
  #use YAML; print Dump $options;
  return _format_bytes($bytes, $options);
}

### the OO way

# new()
sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  my $opts = _parse_args(undef, @_);
  return bless $opts, $class;
}

# set_options()
sub set_options {
  my $self = shift;
  return $self->_parse_args(@_);
}

# format()
sub format {
  my $self = shift;
  my $bytes = shift;
  return _format_bytes($bytes, $self);
}


# the solution by COG in Filesys::DiskUsage 
# convert size to human readable format
#sub _convert {
#  defined (my $size = shift) || return undef;
#  my $config = {@_};
#  $config->{human} || return $size;
#  my $block = $config->{'Human-readable'} ? 1000 : 1024;
#  my @args = qw/B K M G/;
#
#  while (@args && $size > $block) {
#    shift @args;
#    $size /= $block;
#  }
#
#  if ($config->{'truncate-readable'} > 0) {
#    $size = sprintf("%.$config->{'truncate-readable'}f",$size);
#  }
#
#  "$size$args[0]";
#}
#
# not exact: 1024 => 1024B instead of 1K
# not nicely formatted => 1.00 instead of 1K

1;


#! /usr/bin/false
#
# $Id: MD5.pm,v 1.19 2004/02/14 02:25:32 lackas Exp $
#

# the POD was stripped to save space

package MD5;
use strict;
use integer;
use Exporter;
use vars qw($VERSION @ISA @EXPORTER @EXPORT_OK);

@EXPORT_OK = qw(md5 md5_hex md5_base64);

@ISA = 'Exporter';
$VERSION = '1.6';

# I-Vektor
sub A() { 0x67_45_23_01 }
sub B() { 0xef_cd_ab_89 }
sub C() { 0x98_ba_dc_fe }
sub D() { 0x10_32_54_76 }

# for internal use
sub MAX() { 0xFFFFFFFF }

# padd a message to a multiple of 64
sub padding {
    my $l = length (my $msg = shift() . chr(128));
    $msg .= "\0" x (($l%64<=56?56:120)-$l%64);
    $l = ($l-1)*8;
    $msg .= pack 'VV', $l & MAX , ($l >> 16 >> 16);
}


sub rotate_left($$) {
	#$_[0] << $_[1] | $_[0] >> (32 - $_[1]);
	#my $right = $_[0] >> (32 - $_[1]);
	#my $rmask = (1 << $_[1]) - 1;
	($_[0] << $_[1]) | (( $_[0] >> (32 - $_[1])  )  & ((1 << $_[1]) - 1));
	#$_[0] << $_[1] | (($_[0]>> (32 - $_[1])) & (1 << (32 - $_[1])) - 1);
}

sub gen_code {
  # Discard upper 32 bits on 64 bit archs.
  my $MSK = ((1 << 16) << 16) ? ' & ' . MAX : '';
#	FF => "X0=rotate_left(((X1&X2)|(~X1&X3))+X0+X4+X6$MSK,X5)+X1$MSK;",
#	GG => "X0=rotate_left(((X1&X3)|(X2&(~X3)))+X0+X4+X6$MSK,X5)+X1$MSK;",
  my %f = (
	FF => "X0=rotate_left((X3^(X1&(X2^X3)))+X0+X4+X6$MSK,X5)+X1$MSK;",
	GG => "X0=rotate_left((X2^(X3&(X1^X2)))+X0+X4+X6$MSK,X5)+X1$MSK;",
	HH => "X0=rotate_left((X1^X2^X3)+X0+X4+X6$MSK,X5)+X1$MSK;",
	II => "X0=rotate_left((X2^(X1|(~X3)))+X0+X4+X6$MSK,X5)+X1$MSK;",
  );
  #unless ( (1 << 16) << 16) { %f = %{$CODES{'32bit'}} }
  #else { %f = %{$CODES{'64bit'}} }

  my %s = (  # shift lengths
	S11 => 7, S12 => 12, S13 => 17, S14 => 22, S21 => 5, S22 => 9, S23 => 14,
	S24 => 20, S31 => 4, S32 => 11, S33 => 16, S34 => 23, S41 => 6, S42 => 10,
	S43 => 15, S44 => 21
  );

  my $insert = "";
  while(<DATA>) {
	chomp;
	next unless /^[FGHI]/;
	my ($func,@x) = split /,/;
	my $c = $f{$func};
	$c =~ s/X(\d)/$x[$1]/g;
	$c =~ s/(S\d{2})/$s{$1}/;
        $c =~ s/^(.*)=rotate_left\((.*),(.*)\)\+(.*)$//;

	#my $rotate = "(($2 << $3) || (($2 >> (32 - $3)) & (1 << $2) - 1)))";
	$c = "\$r = $2;
        $1 = ((\$r << $3) | ((\$r >> (32 - $3))  & ((1 << $3) - 1))) + $4";
	$insert .= "\t$c\n";
  }
  close DATA;

  my $dump = '
  sub round {
	my ($a,$b,$c,$d) = @_[0 .. 3];
	my $r;

	' . $insert . '
	$_[0]+$a' . $MSK . ', $_[1]+$b ' . $MSK .
        ', $_[2]+$c' . $MSK . ', $_[3]+$d' . $MSK . ';
  }';
  eval $dump;
  #print "$dump\n";
  #exit 0;
}

gen_code();

#########################################
# Private output converter functions:
sub _encode_hex { unpack 'H*', $_[0] }
sub _encode_base64 {
	my $res;
	while ($_[0] =~ /(.{1,45})/gs) {
		$res .= substr pack('u', $1), 1;
		chop $res;
	}
	$res =~ tr|` -_|AA-Za-z0-9+/|;#`
	chop $res; chop $res;
	$res
}

#########################################
# OOP interface:
sub new {
	my $proto = shift;
	my $class = ref $proto || $proto;
	my $self = {};
	bless $self, $class;
	$self->reset();
	$self
}

sub reset {
	my $self = shift;
	delete $self->{_data};
	$self->{_state} = [A,B,C,D];
	$self->{_length} = 0;
	$self
}

sub add {
	my $self = shift;
	$self->{_data} .= join '', @_ if @_;
	my ($i,$c);
	for $i (0 .. (length $self->{_data})/64-1) {
		my @X = unpack 'V16', substr $self->{_data}, $i*64, 64;
		@{$self->{_state}} = round(@{$self->{_state}},@X);
		++$c;
	}
	if ($c) {
		substr $self->{_data}, 0, $c*64, '';
		$self->{_length} += $c*64;
	}
	$self
}

sub finalize {
	my $self = shift;
	$self->{_data} .= chr(128);
    my $l = $self->{_length} + length $self->{_data};
    $self->{_data} .= "\0" x (($l%64<=56?56:120)-$l%64);
    $l = ($l-1)*8;
    $self->{_data} .= pack 'VV', $l & MAX , ($l >> 16 >> 16);
	$self->add();
	$self
}

sub addfile {
  	my ($self,$fh) = @_;
	if (!ref($fh) && ref(\$fh) ne "GLOB") {
	    require Symbol;
	    $fh = Symbol::qualify($fh, scalar caller);
	}
	# $self->{_data} .= do{local$/;<$fh>};
	my $read = 0;
	my $buffer = '';
	$self->add($buffer) while $read = read $fh, $buffer, 8192;
	die __PACKAGE__, " read failed: $!" unless defined $read;
	$self
}

sub add_bits {
}

sub digest {
	my $self = shift;
	$self->finalize();
	my $res = pack 'V4', @{$self->{_state}};
	$self->reset();
	$res
}

sub hexdigest {
	_encode_hex($_[0]->digest)
}

sub b64digest {
	_encode_base64($_[0]->digest)
}

sub clone {
	my $self = shift;
	my $clone = {
		_state => [@{$self->{_state}}],
		_length => $self->{_length},
		_data => $self->{_data}
	};
	bless $clone, ref $self || $self;
}

#########################################
# Procedural interface:
sub md5 {
	my $message = padding(join'',@_);
	my ($a,$b,$c,$d) = (A,B,C,D);
	my $i;
	for $i (0 .. (length $message)/64-1) {
		my @X = unpack 'V16', substr $message,$i*64,64;
		($a,$b,$c,$d) = round($a,$b,$c,$d,@X);
	}
	pack 'V4',$a,$b,$c,$d;
}
sub md5_hex { _encode_hex &md5 }
sub md5_base64 { _encode_base64 &md5 }


1;

__DATA__
FF,$a,$b,$c,$d,$_[4],7,0xd76aa478,/* 1 */
FF,$d,$a,$b,$c,$_[5],12,0xe8c7b756,/* 2 */
FF,$c,$d,$a,$b,$_[6],17,0x242070db,/* 3 */
FF,$b,$c,$d,$a,$_[7],22,0xc1bdceee,/* 4 */
FF,$a,$b,$c,$d,$_[8],7,0xf57c0faf,/* 5 */
FF,$d,$a,$b,$c,$_[9],12,0x4787c62a,/* 6 */
FF,$c,$d,$a,$b,$_[10],17,0xa8304613,/* 7 */
FF,$b,$c,$d,$a,$_[11],22,0xfd469501,/* 8 */
FF,$a,$b,$c,$d,$_[12],7,0x698098d8,/* 9 */
FF,$d,$a,$b,$c,$_[13],12,0x8b44f7af,/* 10 */
FF,$c,$d,$a,$b,$_[14],17,0xffff5bb1,/* 11 */
FF,$b,$c,$d,$a,$_[15],22,0x895cd7be,/* 12 */
FF,$a,$b,$c,$d,$_[16],7,0x6b901122,/* 13 */
FF,$d,$a,$b,$c,$_[17],12,0xfd987193,/* 14 */
FF,$c,$d,$a,$b,$_[18],17,0xa679438e,/* 15 */
FF,$b,$c,$d,$a,$_[19],22,0x49b40821,/* 16 */
GG,$a,$b,$c,$d,$_[5],5,0xf61e2562,/* 17 */
GG,$d,$a,$b,$c,$_[10],9,0xc040b340,/* 18 */
GG,$c,$d,$a,$b,$_[15],14,0x265e5a51,/* 19 */
GG,$b,$c,$d,$a,$_[4],20,0xe9b6c7aa,/* 20 */
GG,$a,$b,$c,$d,$_[9],5,0xd62f105d,/* 21 */
GG,$d,$a,$b,$c,$_[14],9,0x2441453,/* 22 */
GG,$c,$d,$a,$b,$_[19],14,0xd8a1e681,/* 23 */
GG,$b,$c,$d,$a,$_[8],20,0xe7d3fbc8,/* 24 */
GG,$a,$b,$c,$d,$_[13],5,0x21e1cde6,/* 25 */
GG,$d,$a,$b,$c,$_[18],9,0xc33707d6,/* 26 */
GG,$c,$d,$a,$b,$_[7],14,0xf4d50d87,/* 27 */
GG,$b,$c,$d,$a,$_[12],20,0x455a14ed,/* 28 */
GG,$a,$b,$c,$d,$_[17],5,0xa9e3e905,/* 29 */
GG,$d,$a,$b,$c,$_[6],9,0xfcefa3f8,/* 30 */
GG,$c,$d,$a,$b,$_[11],14,0x676f02d9,/* 31 */
GG,$b,$c,$d,$a,$_[16],20,0x8d2a4c8a,/* 32 */
HH,$a,$b,$c,$d,$_[9],4,0xfffa3942,/* 33 */
HH,$d,$a,$b,$c,$_[12],11,0x8771f681,/* 34 */
HH,$c,$d,$a,$b,$_[15],16,0x6d9d6122,/* 35 */
HH,$b,$c,$d,$a,$_[18],23,0xfde5380c,/* 36 */
HH,$a,$b,$c,$d,$_[5],4,0xa4beea44,/* 37 */
HH,$d,$a,$b,$c,$_[8],11,0x4bdecfa9,/* 38 */
HH,$c,$d,$a,$b,$_[11],16,0xf6bb4b60,/* 39 */
HH,$b,$c,$d,$a,$_[14],23,0xbebfbc70,/* 40 */
HH,$a,$b,$c,$d,$_[17],4,0x289b7ec6,/* 41 */
HH,$d,$a,$b,$c,$_[4],11,0xeaa127fa,/* 42 */
HH,$c,$d,$a,$b,$_[7],16,0xd4ef3085,/* 43 */
HH,$b,$c,$d,$a,$_[10],23,0x4881d05,/* 44 */
HH,$a,$b,$c,$d,$_[13],4,0xd9d4d039,/* 45 */
HH,$d,$a,$b,$c,$_[16],11,0xe6db99e5,/* 46 */
HH,$c,$d,$a,$b,$_[19],16,0x1fa27cf8,/* 47 */
HH,$b,$c,$d,$a,$_[6],23,0xc4ac5665,/* 48 */
II,$a,$b,$c,$d,$_[4],6,0xf4292244,/* 49 */
II,$d,$a,$b,$c,$_[11],10,0x432aff97,/* 50 */
II,$c,$d,$a,$b,$_[18],15,0xab9423a7,/* 51 */
II,$b,$c,$d,$a,$_[9],21,0xfc93a039,/* 52 */
II,$a,$b,$c,$d,$_[16],6,0x655b59c3,/* 53 */
II,$d,$a,$b,$c,$_[7],10,0x8f0ccc92,/* 54 */
II,$c,$d,$a,$b,$_[14],15,0xffeff47d,/* 55 */
II,$b,$c,$d,$a,$_[5],21,0x85845dd1,/* 56 */
II,$a,$b,$c,$d,$_[12],6,0x6fa87e4f,/* 57 */
II,$d,$a,$b,$c,$_[19],10,0xfe2ce6e0,/* 58 */
II,$c,$d,$a,$b,$_[10],15,0xa3014314,/* 59 */
II,$b,$c,$d,$a,$_[17],21,0x4e0811a1,/* 60 */
II,$a,$b,$c,$d,$_[8],6,0xf7537e82,/* 61 */
II,$d,$a,$b,$c,$_[15],10,0xbd3af235,/* 62 */
II,$c,$d,$a,$b,$_[6],15,0x2ad7d2bb,/* 63 */
II,$b,$c,$d,$a,$_[13],21,0xeb86d391,/* 64 */



1;


