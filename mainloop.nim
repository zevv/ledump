
import std / [posix, tables, sequtils, sets, hashes]
import npeg

type

  Linesplitter = ref object
    buf: string
    fn: proc(s: string)

  FdHandlerFn = proc(fd: cint): bool

  TimerHandlerFn = proc(): bool

  FdHandler = ref object
    fd: cint
    events: int16
    fn: FdHandlerFn

  TimerHandler = ref object
    interval: float
    t_next: float
    fn: TimerHandlerFn

  MainLoop* = ref object
    t_now: float
    fds: HashSet[FdHandler]
    timers: HashSet[TimerHandler]


proc hash(th: TimerHandler): Hash =
  result = hash(th.fn)

proc hash(fh: FdHandler): Hash =
  result = hash(fh.fn)


proc hirestime(): float = 
  var ts : posix.Timespec
  discard posix.clock_gettime(posix.CLOCK_MONOTONIC, ts)
  result = float(ts.tv_sec) + float(ts.tv_nsec) / 1_000_000_000.0


proc newMainLoop*(): MainLoop =
  new result


proc time*(mainloop: MainLoop): float =
  result = mainloop.t_now


proc add_fd(mainloop: MainLoop, fd: cint, events: int16, fn: FdHandlerFn): FdHandler =
  var fh = new FdHandler
  fh.fd = fd
  fh.events = events
  fh.fn = fn
  mainloop.fds.incl fh
  fh


proc del_fd(mainloop: MainLoop, fh: FdHandler) =
  mainloop.fds.excl fh


proc add_timer*(mainloop: Mainloop, interval: float, fn: TimerHandlerFn): TimerHandler =
  var th = new TimerHandler
  th.interval = interval
  th.t_next = hirestime() + interval
  th.fn = fn
  mainloop.timers.incl th
  th


proc del_timer(mainloop: MainLoop, th: TimerHandler) =
  mainloop.timers.excl th


proc get_next_timeout_ms(mainloop: MainLoop): cint =
  if mainloop.timers.len == 0:
    return -1
  let t_next = mainloop.timers.mapIt(it.t_next).min
  if t_next <= mainloop.t_now:
    return 0
  else:
    return cint((t_next - mainloop.t_now) * 1000.0) + 1
  

proc handle_timers(mainloop: MainLoop) =
  var to_delete: seq[TimerHandler]
  for th in mainloop.timers:
    if mainloop.t_now >= th.t_next:
      let keep = th.fn()
      if keep:
        th.t_next = mainloop.t_now + th.interval
      else:
        to_delete.add th
  for th in to_delete:
    mainloop.del_timer(th)



proc run_one(mainloop: MainLoop): bool =

  mainloop.t_now = hirestime()
  mainloop.handle_timers()

  var fds = newSeq[posix.TPollfd](mainloop.fds.len)
  var i = 0
  for fh in mainloop.fds:
    fds[i].fd = fh.fd
    fds[i].events = fh.events
    fds[i].revents = 0
    inc i

  let timeout = mainloop.get_next_timeout_ms()
  let nfds = fds.len

  if timeout == -1 and nfds == 0:
    return false

  let fdsaddr = if nfds > 0: addr fds[0] else: nil

  let nfds_ready = posix.poll(fdsaddr, fds.len.uint, timeout)
 
  mainloop.t_now = hirestime()
  mainloop.handle_timers()

  var to_delete: seq[FdHandler]
  if nfds_ready > 0:
    for fd in fds:
      if fd.revents != 0:
        for fh in mainloop.fds:
          if fh.fd == fd.fd:
            let keep = fh.fn(fh.fd)
            if not keep:
              to_delete.add fh
            break

  for fh in to_delete:
    mainloop.del_fd(fh)

  return true



proc run*(mainloop: MainLoop) =
  while mainloop.run_one():
    discard
  echo "mainloop exit"


proc newLineSplitter(fn: proc(s: string)): LineSplitter =
  new result
  result.fn = fn


proc put(ls: var LineSplitter, data: string) =
  
  let p = peg(lines, ls: LineSplitter):
    lines <- *line
    line <- >+(1-'\n') * '\n':
      ls.fn($1)

  ls.buf.add data
  let r = p.match(ls.buf, ls)
  ls.buf = ls.buf[r.matchLen..^1]


proc spawn*(mainloop: MainLoop, cmd: string, on_line: proc(l: string)) =
  var fds: array[2, cint]
  discard posix.pipe(fds)

  let pid = posix.fork()
  if pid == 0:
    discard posix.close(fds[0])
    discard posix.dup2(fds[1], posix.STDOUT_FILENO)
    discard posix.dup2(fds[1], posix.STDERR_FILENO)
    discard posix.close(fds[1])
    let args = ["/bin/sh", "-c", cmd]
    discard posix.execvp("/bin/sh", allocCStringArray(args))
    echo "execvp failed"
    quit(1)

  var splitter = newLineSplitter(on_line)
  var buf = newString(1024)
  proc on_data(fd: cint): bool =
    let n = posix.read(fd, addr buf[0], buf.len)
    if n > 0:
       splitter.put(buf[0..n-1])
       return true

  discard posix.close(fds[1])

  discard mainloop.add_fd(fds[0], posix.POLLIN, on_data)

