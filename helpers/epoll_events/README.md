### epoll events for socket
|socket state|events|
|------------|------|
|just created(disconnected)|OUT, HUP|
|connected|OUT|
|read ready|IN, OUT|
|------------------|---------------|
|peer SHUT_RD|IN, OUT (nothing changed)|
|peer SHUT_WR|IN, OUT, RDHUP|
|peer SHUT_RDWR|IN, OUT, RDHUP|
|peer closed socket| IN, OUT, RDHUP|
|------------------|---------------|
|client SHUT_RD|IN, OUT, RDHUP|
|client SHUT_WR|IN, OUT (reported twice)|
|client SHUT_RDWR|IN, OUT, RDHUP, HUP (reported twice)|

New epoll events (in EPOLLET mode) reported when they appear,
so if I read all data from socket (with closed peer end),
new event without EPOLLIN will not be reported. After write
to socket with closed peer end I got error and events:
`IN, OUT, RDHUP, ERR, HUP` so I can't detect if socket
readable or not (it can have data in kernel buffer even with
`RDHUP` and `HUP`). `IN` with `HUP` can be set for empty
socket (without data in kernel buffer).

So socket with `HUP` is not writable. But with any events it
can be readable (if `IN` cleared - it's not readable, if set -
I need to try to read). Also socket can detect it's `HUP`
after failed send (async_send will return successful write).

### rules
Try to send if `OUT` set but no `HUP`.

Try to read if `IN` is set.
