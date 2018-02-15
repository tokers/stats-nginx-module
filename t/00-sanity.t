use lib 'lib';
use Test::Nginx::Socket 'no_plan';

our $http_config = << 'EOC';
    stats_format main '$body_bytes_sent ${remote_addr:i}'
    stats_zone $http_foo zone=stats:10m format=main;
EOC

no_long_string();
#repeact_each(3);
run_tests();

__DATA__

=== TEST 1: sanity test
--- config
location = /echo {
    stats_echo zone=stats;
}

location = /t {
    return 200 "Hello World";
    stats zone=stats;
}

--- pipelined_requests eval
["GET /t", "GET /t", "GET /echo"]

--- more_headers
Foo: bar

--- response_body eval
["", "", "22 127.0.0.1"]

--- no_error_log
[error]
