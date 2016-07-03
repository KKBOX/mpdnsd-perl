use Module::Build;

Module::Build->new(
    module_name => 'mpdnsd',
    license => 'BSD',
    dist_abstract => 'mpdnsd',
    dist_version => '0.0.20160615',
    requires => {
        'File::Write::Rotate' => '',
        'Geo::IP' => '',
        'Net::DNS' => '',
    },
    build_requires => {
        'Test::Exception' => '',
        'Test::MockModule' => '',
        'Test::MockObject' => '',
        'Test::More' => '',
    },
)->create_build_script;
