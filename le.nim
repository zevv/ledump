
import std / [ tables, strutils, strformat, hashes, sets, posix ]
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

  Characteristic = ref object
    uuid: string
    handle: int
    properties: int
    value_handle: int
    value: string

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

  Scanner = ref object
    loop: MainLoop
    nodes: Table[BtAddr, Node]
    btmon_data: seq[string]
 


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




proc dump(node: Node, evtype: string, blob: string) =
  let fname = &"dump/le-{node.btaddr}-{evtype}.log"
  let f = open(fname, fmWrite)
  f.write(blob)
  f.close()


proc discover_characteristics(scanner: Scanner, node: Node, service: Service) =

  # handle = 0x0002, char properties = 0x02, char value handle = 0x0003, uuid = 00002a00-0000-1000-8000-00805f9b34fb
  let p = peg("characteristic", c: Characteristic):
    characteristic <- handle * props * value * uuid:
      c.handle = fromHex[int]($1)
      c.properties = fromHex[int]($2)
      c.value_handle = fromHex[int]($3)
      c.uuid = $4
    handle <- "handle = " * >("0x" * +Xdigit) * ", "
    props <- "char properties = " * >("0x" * +Xdigit) * ", "
    value <- "char value handle = " * >("0x" * +Xdigit) * ", "
    uuid <- "uuid = " * >+(Xdigit | '-')

  proc on_line(l: string) =
    var c = new Characteristic
    let r = p.match(l, c)
    if r.ok:
      service.characteristics[c.uuid] = c
      echo "- " , uuid_name(c.uuid)
    else:
      echo "failed to parse characteristic line at pos ", r.matchLen

  echo "-  Discovering characteristics on ", node.btaddr, " service ", service.uuid
  scanner.loop.spawn(&"sudo gatttool -b {node.btaddr} --characteristics --start={service.start_handle} --end={service.end_handle}", on_line)


proc discover_services(scanner: Scanner, node: Node) =

  let p = peg("service", s: Service):
    service <- start_handle * end_handle * uuid:
      s.start_handle = fromHex[int]($1)
      s.end_handle = fromHex[int]($2)
      s.uuid = $3
    start_handle <- "attr handle = " * >("0x" * +Xdigit) * ", "
    end_handle <- "end grp handle = " * >("0x" * +Xdigit) * " "
    uuid <- "uuid: " * >+(Xdigit | '-')
  
  proc on_line(l: string) =
    var s = new Service
    let r = p.match(l, s)
    if r.ok:
      echo "- " , uuid_name(s.uuid)
      node.services[s.uuid] = s
      scanner.discover_characteristics(node, s)
    else:
      echo "failed to parse service line at pos ", r.matchLen

  echo "- Discovering services on ", node.btaddr
  scanner.loop.spawn(&"sudo gatttool -b {node.btaddr} --primary", on_line)



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
      #  scanner.discover_services(node)
      

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
  
  scanner.loop.spawn("sudo btmon --color never", on_btmon)

  proc on_bluetoothctl(l: string) =
    #echo "c> ", l
    discard
  scanner.loop.spawn("sudo bluetoothctl -t -1 scan le", on_bluetoothctl)
  scanner.loop.spawn("sudo bluetoothctl -t -1 scan on", on_bluetoothctl)

  scanner.loop.add_timer(0.5, proc(): bool =
    #scanner.dump()
    scanner.cleanup()
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

