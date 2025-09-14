
import std / [ tables, strutils, strformat, hashes, sets, posix, deques ]
import mainloop
import npeg

let well_known_services = {
  0x1800: "Generic Access",
  0x1801: "Generic Attribute",
  0x180F: "Battery Service",
  0x1812: "Human Interface Device",
  0x181A: "Environmental Sensing",
  0x181B: "Body Composition",
  0x181C: "User Data",
  0x181D: "Weight Scale",
  0x180A: "Device Information",
  0x180D: "Heart Rate",
  0x180E: "Phone Alert Status Service",
  0x180F: "Battery Service",
  0x1810: "Blood Pressure",
  0x1811: "Alert Notification Service",
  0x1813: "Cycling Speed and Cadence",
  0x1814: "Cycling Power",
  0x1815: "Location and Navigation",

  0x2800: "Primary Service",
  0x2801: "Secondary Service",
  0x2803: "Characteristic",
  0x2901: "Characteristic User Description",
  0x2902: "Client Characteristic Configuration",
  0x2903: "Server Characteristic Configuration",
  0x2904: "Characteristic Presentation Format",
  0x2a01: "Device Name",
  
  0x2a00: "Device Name",
  0x2a01: "Appearance",

}.toTable()


type

  BtAddr = string

  Uuid = string
  
  AddressType = enum
    Unknown
    Public
    Random

  Descriptor = ref object
    uuid: string
    handle: int
    value: string

  Characteristic = ref object
    uuid: string
    handle: int
    properties: int
    value_handle: int
    value: string
    descriptors: Table[Uuid, Descriptor]

  Service = ref object
    uuid: string
    start_handle: int
    end_handle: int
    characteristics: Table[Uuid, Characteristic]

  Node = ref object
    t_last_seen: float
    btaddr: BtAddr
    address_type: AddressType
    name: string
    company: string
    class: string
    rssi: int
    service_data: string
    fingerprint: Hash
    services: Table[Uuid, Service]

  WorkResultFn = proc(ok: bool)

  WorkFn = proc(fn_res: WorkResultFn)

  Work = ref object
    t_scheduled: float
    t_started: float
    id: int
    name: string
    fn: WorkFn

  Scanner = ref object
    loop: MainLoop
    nodes: Table[BtAddr, Node]
    btmon_data: seq[string]
    workIdSeq: int
    workQueue: Deque[Work]
    workActive: Work
 


proc newScanner(loop: MainLoop): Scanner =
  new result
  result.loop = loop

proc `$`(at: AddressType): string =
  case at
    of AddressType.Unknown: "?"
    of AddressType.Public: " "
    of AddressType.Random: "R"


proc uuid_name(uuid: Uuid): string =
  let p = peg("wellknown"):
    wellknown <- long | short
    long <- "0000" * short * "-0000-1000-8000-00805f9b34fb"
    short <- >+Xdigit[4]
  let r = p.match(uuid)
  if r.ok:
    let short = fromHex[int](r.captures[0])
    if well_known_services.contains(short):
      return &"{well_known_services[short]} ({short:04x})"
    else:
      return uuid
    


type

  EvType = enum
    DeviceFound
    MetaEvent
    ExtInquiryResult

  Evdata = object
    evtype: EvType
    btaddr: BtAddr
    address_type: AddressType
    rssi: int
    name: string
    company: string
    class: string
    service_data: string


proc work_add(scanner: Scanner, name: string, fn: WorkFn) =
  let work = new Work
  work.id = scanner.workIdSeq
  work.t_scheduled = scanner.loop.time()
  work.name = name
  work.fn = fn
  scanner.workQueue.addLast (work)
  scanner.workIdSeq += 1
  echo &">> work {work.id}: {name} queued"


proc work_run(scanner: Scanner) =

  if scanner.workActive != nil:
    let age = scanner.loop.time() - scanner.workActive.t_started
    echo &">> work: active {scanner.workActive.id}: {scanner.workActive.name} ({age:.1f}s)"
    return

  if scanner.workQueue.len == 0:
    echo ">> work: idle"
    return

  scanner.workActive = scanner.workQueue.popFirst()
  echo &">> work {scanner.workActive.id}: {scanner.workActive.name} start"

  proc work_cb(ok: bool) =
    echo &">> work {scanner.workActive.id}: { scanner.workActive.name} done: {ok}"
    if not ok:
      scanner.workQueue.addLast(scanner.workActive)
    scanner.workActive = nil
    scanner.work_run()
  
  scanner.workActive.t_started = scanner.loop.time()
  scanner.workActive.fn(work_cb)


proc dump(node: Node, evtype: string, blob: string) =
  let fname = &"dump/le-{node.btaddr}-{evtype}.log"
  let f = open(fname, fmWrite)
  f.write(blob)
  f.close()


proc discover_descriptors(scanner: Scanner, node: Node, characteristic: Characteristic) =
    
  # handle = 0x0001, uuid = 00002800-0000-1000-8000-00805f9b34fb

  let p = peg("descriptors", ds: Table[Uuid, Descriptor]):
    descriptors <- +descriptor
    descriptor <- handle * uuid * '\n':
      let desc = new Descriptor
      desc.handle = fromHex[int]($1)
      desc.uuid = $2
      ds[desc.uuid] = desc
    handle <- "handle: " * >("0x" * +Xdigit) * ", "
    uuid <- "uuid: " * >+(Xdigit | '-')

  proc work(fn_res: WorkResultFn) =

    proc on_data(s: string) =
      var ds: Table[Uuid, Descriptor]
      let r = p.match(s, ds)
      if r.ok:
        characteristic.descriptors = ds
      else:
        echo "failed to parse descriptor line at pos ", r.matchLen
        echo s
      fn_res(true)

    scanner.loop.spawn(@[
      "gatttool",
      "-b", node.btaddr,
      "--char-desc",
      "--start", &"0x{characteristic.handle:04x}",
      "--end", $"0x{characteristic.value_handle:04x}"
    ], on_data)
   
  scanner.work_add(&"discover_descriptors for {node.btaddr} {characteristic.uuid}", work)


proc discover_characteristics(scanner: Scanner, node: Node, service: Service) =

  let p = peg("characteristics", cs: Table[Uuid, Characteristic]):
    characteristics <- +characteristic
    characteristic <- handle * props * value * uuid * '\n':
      let c = new Characteristic
      c.handle = fromHex[int]($1)
      c.properties = fromHex[int]($2)
      c.value_handle = fromHex[int]($3)
      c.uuid = $4
      cs[c.uuid] = c
    handle <- "handle = " * >("0x" * +Xdigit) * ", "
    props <- "char properties = " * >("0x" * +Xdigit) * ", "
    value <- "char value handle = " * >("0x" * +Xdigit) * ", "
    uuid <- "uuid = " * >+(Xdigit | '-')

  proc work(fn_res: WorkResultFn) =

    proc on_data(l: string) =
      var cs: Table[Uuid, Characteristic]
      let r = p.match(l, cs)
      if r.ok:
        service.characteristics = cs
        for c in cs.values:
          scanner.discover_descriptors(node, c)
        fn_res(true)
      else:
        echo "failed to parse characteristic line at pos ", r.matchLen
        fn_res(false)

    scanner.loop.spawn(@[
      "gatttool",
      "-b", node.btaddr,
      "--characteristics",
      "--start", $service.start_handle,
      "--end", $service.end_handle
    ], on_data)


  scanner.work_add(&"discover_characteristics for {node.btaddr} {service.uuid}", work)




proc discover_services(scanner: Scanner, node: Node) =

  let p = peg("services", ss: Table[Uuid, Service]):
    services <- +service
    service <- start_handle * end_handle * uuid * '\n':
      let s = new Service
      s.start_handle = fromHex[int]($1)
      s.end_handle = fromHex[int]($2)
      s.uuid = $3
      ss[s.uuid] = s
    start_handle <- "attr handle = " * >("0x" * +Xdigit) * ", "
    end_handle <- "end grp handle = " * >("0x" * +Xdigit) * " "
    uuid <- "uuid: " * >+(Xdigit | '-')
  
  proc work(fn_res: WorkResultFn) =

    proc on_stdout(l: string) =
      echo l
      var ss: Table[Uuid, Service]
      let r = p.match(l, ss)
      if r.ok:
        for s in ss.values:
          echo "  - Service ", uuid_name(s.uuid), " handles ", $s.start_handle, "-", $s.end_handle
          scanner.discover_characteristics(node, s)
        node.services = ss
        fn_res(true)
      else:
        echo "failed to parse service line at pos ", r.matchLen
        fn_res(false)

    scanner.loop.spawn(@[
      "gatttool",
      "-b", node.btaddr,
      "--primary"
    ], on_stdout)

  scanner.work_add(&"discover_services for {node.btaddr}", work)



proc handle_btmon(scanner: Scanner, lines: seq[string]) =

  let p = peg("btmon", ev: Evdata):
    S <- *' '
    btmon <- event_device_found | event_le_meta | event_ext: ev.evtype = MetaEvent
    event_device_found <- "@ MGMT Event: Device Found" * rest * lines: ev.evtype = DeviceFound
    event_le_meta <- "> HCI Event: LE Meta Event" * rest * lines: ev.evtype = MetaEvent
    event_ext <- "> HCI Event: Extended Inquiry Result" * rest * lines
    lines <- +(line * '\n')
    line <- S * (le_address | rssi | name | company | address_type | class | service_data | other)
    le_address <- "Address: " * >btaddr * rest: ev.btaddr = $1
    rssi <- "RSSI: " * >int * rest: ev.rssi = parseInt($1)
    name <- "Name (complete): " * >rest: ev.name = $1
    company <- "Company: " * >+Alnum * rest: ev.company = $1
    class <- "Minor class: " * >rest: ev.class = $1
    address_type <- "Address type: " * (address_type_public | address_type_random) * rest
    address_type_public <- "Public": ev.address_type = AddressType.Public
    address_type_random <- "Random": ev.address_type = AddressType.Random
    service_data <- "Data[" * int * "]: " * >rest: ev.service_data = $1
    other <- >rest: discard
    rest <- *(1-'\n')
    btaddr <- twohex * ':' * twohex * ':' * twohex * ':' * twohex * ':' * twohex * ':' * twohex
    twohex <- Xdigit * Xdigit
    int <- ?{'+', '-'} * +Digit

  let blob = lines.join("\n")
  var ev: Evdata
  let r = p.match(blob, ev)
  if not r.ok:
    if false:
      echo "failed to parse at pos ", r.matchLen
      echo "----"
      echo blob
      echo "----"
    
  if ev.btaddr != "":
    #echo ev
    var node = scanner.nodes.getOrDefault(ev.btaddr, nil)
    if node == nil:
      node = Node(btaddr: ev.btaddr)
      scanner.nodes[ev.btaddr] = node
      #if ev.btaddr == "74:46:B3:84:EF:78":
      if true:
        scanner.discover_services(node)
      

    node.t_last_seen = scanner.loop.time()

    if ev.name != "":
      node.name = ev.name
    if ev.company != "":
      node.company = ev.company
    if ev.rssi != 0:
      node.rssi = ev.rssi
    if ev.class != "":
      node.class = ev.class
    if ev.address_type != AddressType.Unknown:
      node.address_type = ev.address_type
    if ev.service_data != "":
      node.service_data = ev.service_data

    node.fingerprint = hash(node.name) !& hash(node.company) !& hash($node.address_type) !& hash($node.class) !& hash(node.service_data)

    #node.dump($ev.evtype, blob) 


proc dump(scanner: Scanner) =
  #echo "\e[2J\e[H"
  echo "--------------------------------"
  for n in scanner.nodes.values:
    let age = scanner.loop.time() - n.t_last_seen
    echo &"{n.btaddr} ({n.address_type}) {age:4.1f} {n.rssi:+4d} {n.name:20} {n.company:20} {n.class:10}"
    for s in n.services.values:
      echo &"  - {s.start_handle:04x}-{s.end_handle:04x}: Service {uuid_name(s.uuid)}"
      for c in s.characteristics.values:
        echo &"    - {c.handle:04x}: {uuid_name(c.uuid)} props {c.properties:02x} value_handle {c.value_handle:04x}"
        for d in c.descriptors.values:
          echo &"      - {d.handle:04x}: {uuid_name(d.uuid)} value {d.value}"


proc cleanup(scanner: Scanner) =
  
  var to_delete: HashSet[BtAddr]

  # remove nodes not seen for a while
  for n in scanner.nodes.values:
    let age = scanner.loop.time() - n.t_last_seen
    if age > 60.0:
      to_delete.incl n.btaddr

  # find nodes with duplicate fingerprints, likely a random address change
  for n1 in scanner.nodes.values:
    for n2 in scanner.nodes.values:
      if n1 != n2 and n1.fingerprint == n2.fingerprint:
        if n1.t_last_seen < n2.t_last_seen:
          to_delete.incl n1.btaddr
        else:
          to_delete.incl n2.btaddr

  for a in to_delete:
    scanner.nodes.del a


proc start(scanner: Scanner) =

  proc on_btmon(l: string) =
    if l[0] != ' ':
      scanner.handle_btmon(scanner.btmon_data)
      scanner.btmon_data = @[]
    scanner.btmon_data.add(l)
  
  scanner.loop.spawn_stream(@[
    "sudo", 
    "btmon", 
    "--color", "never"
  ], on_btmon)

  proc scan_work(fn_res: WorkResultFn) =
    echo "- Scanning for LE devices"
    scanner.loop.spawn(@[
      "bluetoothctl",
      "-t", "5",
      "scan", "le"
    ], proc(l: string) =
      fn_res(false)
    )
  scanner.work_add("scan", scan_work)

  scanner.loop.add_timer(0.5, proc(): bool =
    scanner.dump()
    scanner.cleanup()
    scanner.work_run()
    return true
  )



let loop = newMainLoop()

let scanner = newScanner(loop)
scanner.start()

proc onsigterm(signo: cint): bool =
  loop.stop()

loop.add_signal(posix.SIGTERM, on_sigterm)
loop.add_signal(posix.SIGINT, on_sigterm)

loop.run()

