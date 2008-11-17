use ExtUtils::MakeMaker;
require 5.008;
WriteMakefile(
	NAME => 'Mail::SPF::Iterator',
	VERSION_FROM => 'lib/Mail/SPF/Iterator.pm',
	PREREQ_PM => {
		'Net::DNS' => 0.56,
		'URI' => 0,
	},
);

eval 'require YAML' or 
	warn "YAML is needed to run SPF test suite\n";
