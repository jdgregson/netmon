# netmon
A PowerShell script which makes Windows' netstat command more useful.

     Usage: netmon [args and flags]

      -ShowFullIPv6       Do not truncate IPv6 addresses.
      -NoLocalhost        Do not show connections to or from localhost.
      -AggressiveDNS      Resolve hostnames more thoroughly (but slowly).
      -i, -Incoming       Only show incoming connections.
      -l, -Listening      Display a list of listening ports with associated process
                          names. Only displays ports bound on external interfaces by
                          default. Cannot be combined with any options besides -m.
      -m                  When combined with -l, this option will provide more
                          details, such as PIDs, ports bound on local interfaces,
                          and multiple processes listening on the same port.
      -h, -help           Show this help message.
      -s, -sort           Sort by field, according to the list of fields below.
      -f, -fields         Specify which fields to output, e.g.:
                          'netmon -f ldfP'. Available fields are:
                              l: Local endpoint
                              d: Direction of connection
                              f: Foreign endpoint
                              t: Protocol type
                              s: Connection state
                              h: DNS Hostname
                              i: Process ID
                              p: Process name
                              e: Executable path
                              c: Company
                              *: Display all fields
