[
  {
    'tests' => {
      'sender-id-pick-spf' => {
        'spec' => '',
        'mailfrom' => 'user@example5.net',
        'description' => 'SenderID with mfrom and SPF, pick SPF',
        'result' => 'pass',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      },
      'sender-id-pick-mfrom1' => {
        'spec' => '',
        'mailfrom' => 'user@example3.net',
        'description' => 'SenderID with mfrom and pra, pick mfrom',
        'result' => 'pass',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      },
      'spf-by-cname' => {
        'spec' => '',
        'comment' => 'The SPF Lookup returns a CNAME and the SPF record',
        'mailfrom' => 'user@example.net',
        'description' => 'TXT/SPF records can be referenced through CNAME',
        'result' => 'pass',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      },
      'sender-id-pick-mfrom2' => {
        'spec' => '',
        'mailfrom' => 'user@example4.net',
        'description' => 'SenderID with mfrom and pra, pick mfrom',
        'result' => 'fail',
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
      },
      'domain-dots-at-end' => {
        'spec' => '4.3/1',
        'mailfrom' => 'user@example5.net....',
        'description' => 'multiple dots at end of domain name are illegal',
        'result' => 'none',
        'host' => '1.2.3.5',
        'helo' => 'mail.example.net'
      },
      'sender-id' => {
        'spec' => '',
        'mailfrom' => 'user@example2.net',
        'description' => 'no SPF record but SenderID',
        'result' => 'pass',
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
      'example5.net' => [
        {
          'SPF' => 'spf2.0/mfrom -ip4:1.2.3.5 all'
        },
        {
          'SPF' => 'v=spf1 ip4:1.2.3.5 -all'
        }
      ],
      'example.net' => [
        {
          'CNAME' => 'example.com'
        }
      ],
      'example3.net' => [
        {
          'SPF' => 'spf2.0/pra -ip4:1.2.3.5 all'
        },
        {
          'SPF' => 'spf2.0/mfrom ip4:1.2.3.5 -all'
        }
      ],
      'example2.net' => [
        {
          'SPF' => 'spf2.0/pra,mfrom ip4:1.2.3.5 -all'
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
      ],
      'example4.net' => [
        {
          'SPF' => 'spf2.0/mfrom -ip4:1.2.3.5 all'
        },
        {
          'SPF' => 'spf2.0/pra ip4:1.2.3.5 -all'
        }
      ],
      'example.com' => [
        {
          'SPF' => 'v=spf1 ip4:1.2.3.5 -all'
        }
      ],
      'one.two.three.five.example.net' => [
        {
          'A' => '1.2.3.5'
        }
      ],
      'unknown.explain.example1.net' => [
        {
          'TXT' => 'bad message for %{p}'
        }
      ]
    }
  }
]
