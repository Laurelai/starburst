#!/usr/bin/perl -w
use strict;
use CommonRoutines;
my $config = shift || 'starburst.conf';
if (!registry_init_from_file($config)) {
	print 'Error loading registry: '.$CommonRoutines::error."\n";
	exit;
}
die("Edit your configuration file.\n") if (registry_read('unconfigured'));

plugin_load('core');
registry_read('core')->start;
registry_read('core')->run;