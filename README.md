# fujinet-devrelay-tests

Some python snips for testing the communication
protocol used with fujinet-pc

Port 1985 is used with devrelay

The source code in the src directory is for Snoopy
which monitors the communications between to sockets.
It was specifically written for monitoring between 
fujinet and AppleWin, but it could be used for
any application.
```
Hostname: Ubuntu24
Got config snoopy.cfg:
                                 ...............
                             ....              ..
                            ..                   ..
                           ..                      ..
                         ...                        ..
            .............       ***                  ..
          ..                   *****                  $.
    @@@@@@                      ***     $              $
   @     @                             $   $$$$$$$$    $
  @@@@@@@@                            $   $$$$$$$$$$   $
   @@@@@@@                           $   $$$$$$$$$$$   $
    @@@@@@                           $   $$$$$$$$$$$   $
          ...                        $   $$$$$$$$$$    $
            .............            $$    $$$$$$$   $$
                        ..        ...  $$          $$
                        ..       ..     $$      $$$
                        ..       ..      $$$$$$$$
                        =============
                        =============
Protocol Snooper - Snoopy - By Norman Davie
```

