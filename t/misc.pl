[
  {
    'tests' => {
      'spf-by-cname' => {
        'spec' => '',
        'comment' => 'The SPF Lookup returns a CNAME and the SPF record',
        'mailfrom' => 'user@example.net',
        'description' => 'TXT/SPF records can be referenced through CNAME',
        'result' => 'pass',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      },
      'p-in-exp-mod' => {
        'spec' => '',
        'explanation' => 'forbidden for one.two.three.five.example.net',
        'mailfrom' => 'user@example1.net',
        'description' => '%{p} in exp= modifier',
        'result' => 'fail',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      }
    },
    'description' => 'various other tests',
    'zonedata' => {
      'five.three.two.one.explain.example1.net' => [
        {
          'TXT' => 'forbidden for %{p}'
        }
      ],
      'example.com' => [
        {
          'SPF' => 'v=spf1 ip4:1.2.3.5 -all'
        }
      ],
      'example.net' => [
        {
          'CNAME' => 'example.com'
        }
      ],
      'unknown.explain.example1.net' => [
        {
          'TXT' => 'bad message for %{p}'
        }
      ],
      'one.two.three.five.example.net' => [
        {
          'A' => '1.2.3.5'
        }
      ],
      '5.3.2.1.in-addr.arpa' => [
        {
          'PTR' => 'one.two.three.five.example.net'
        }
      ],
      'example1.net' => [
        {
          'SPF' => 'v=spf1 -ip4:1.2.3.5 all exp=%{p4r}.explain.example1.net'
        }
      ]
    }
  }
]
