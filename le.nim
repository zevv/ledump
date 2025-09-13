
import std / [ tables, strutils, strformat ]
import mainloop
import npeg


type

  BtAddr = string
  
  AddressType = enum
    Unknown
    Public
    Random

  Node = ref object
    t_last_seen: float
    btaddr: BtAddr
    address_type: AddressType
    name: string
    company: string
    class: string
    rssi: int

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

type

  EvType = enum
    DeviceFound

  Evdata = object
    evtype: EvType
    btaddr: BtAddr
    address_type: AddressType
    rssi: int
    name: string
    company: string
    class: string


let p = peg("btmon", ev: Evdata):

  btmon <- event_device_found | event_le_meta | event_ext

  event_device_found <- "@ MGMT Event: Device Found" * rest * lines:
    ev.evtype = DeviceFound

  event_le_meta <- "> HCI Event: LE Meta Event" * rest * lines

  event_ext <- "> HCI Event: Extended Inquiry Result" * rest * lines

  lines <- +(line * '\n')
  line <- S * (le_address | rssi | name | company | address_type | class | other)

  le_address <- "Address: " * >btaddr * rest:
    ev.btaddr = $1

  rssi <- "RSSI: " * >int * rest:
    ev.rssi = parseInt($1)

  name <- "Name (complete): " * >rest:
    ev.name = $1

  company <- "Company: " * >rest:
    ev.company = $1

  class <- "Minor class: " * >rest:
    ev.class = $1

  address_type <- "Address type: " * (address_type_public | address_type_random) * rest
  address_type_public <- "Public": ev.address_type = AddressType.Public
  address_type_random <- "Random": ev.address_type = AddressType.Random

  other <- >rest:
    #echo "other> ", $1
    discard

  rest <- *(1-'\n')



  btaddr <- twohex * ':' * twohex * ':' * twohex * ':' * twohex * ':' * twohex * ':' * twohex
  twohex <- Xdigit * Xdigit
  int <- ?{'+', '-'} * +Digit
  S <- *' '


  var ev: Evdata
  let r = p.match(data, ev)
  echo r.ok
  echo ev
  echo data[0..r.matchLen-1]
  quit(0)



proc handle_btmon(scanner: Scanner, lines: seq[string]) =
  let blob = lines.join("\n")
  var ev: Evdata
  let r = p.match(blob, ev)
  if not r.ok:
    echo "failed to parse at pos ", r.matchLen
    echo "----"
    echo blob
    echo "----"
    return
    
  if ev.btaddr != "":
    #echo ev
    var node = scanner.nodes.getOrDefault(ev.btaddr, nil)
    if node == nil:
      node = Node(btaddr: ev.btaddr)
      scanner.nodes[ev.btaddr] = node

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


proc dump(scanner: Scanner) =
  #echo "\e[2J\e[H"
  echo "--------------------------------"

  var to_delete: seq[BtAddr]

  for n in scanner.nodes.values:
    let age = scanner.loop.time() - n.t_last_seen
    echo &"{n.btaddr} ({n.address_type}) {age:.1f} {n.rssi:+4d} {n.name:20} {n.company:20} {n.class:10}"
    if age > 9.0:
      to_delete.add n.btaddr

  for a in to_delete:
    scanner.nodes.del a



let loop = newMainLoop()
let scanner = newScanner(loop)
scanner.start()

discard loop.add_timer(0.5, proc(): bool =
  scanner.dump()
  return true
)

loop.run()

