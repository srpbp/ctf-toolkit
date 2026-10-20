#!/usr/bin/env python3
"""
usb-keystrokes.py — decode USB HID keyboard capdata from a pcap.

Workflow:
  tshark -r cap.pcap -Y 'usb.capdata' -T fields -e usb.capdata > caps.txt
  usb-keystrokes.py caps.txt

Each line should be hex like `000012000000000000` — byte 0 is modifiers,
byte 2 is the first keycode. See HID Usage Tables for the mapping.

Known gaps: multi-key chords beyond byte 2 are ignored; media keys skipped.
"""
import sys


HID = {
    0x04:"a",0x05:"b",0x06:"c",0x07:"d",0x08:"e",0x09:"f",0x0A:"g",0x0B:"h",
    0x0C:"i",0x0D:"j",0x0E:"k",0x0F:"l",0x10:"m",0x11:"n",0x12:"o",0x13:"p",
    0x14:"q",0x15:"r",0x16:"s",0x17:"t",0x18:"u",0x19:"v",0x1A:"w",0x1B:"x",
    0x1C:"y",0x1D:"z",
    0x1E:"1",0x1F:"2",0x20:"3",0x21:"4",0x22:"5",0x23:"6",0x24:"7",0x25:"8",
    0x26:"9",0x27:"0",
    0x28:"\n",0x29:"<esc>",0x2A:"<bs>",0x2B:"\t",0x2C:" ",
    0x2D:"-",0x2E:"=",0x2F:"[",0x30:"]",0x31:"\\",0x33:";",0x34:"'",
    0x35:"`",0x36:",",0x37:".",0x38:"/",
    0x39:"<caps>",
    0x4F:"<right>",0x50:"<left>",0x51:"<down>",0x52:"<up>",
}
SHIFTED = {
    "1":"!","2":"@","3":"#","4":"$","5":"%","6":"^","7":"&","8":"*","9":"(","0":")",
    "-":"_","=":"+","[":"{","]":"}","\\":"|",";":":","'":"\"","`":"~",",":"<",".":">","/":"?",
}


def decode(path: str) -> str:
    out = []
    with open(path) as f:
        prev = None
        for line in f:
            h = line.strip().replace(":", "")
            if len(h) < 6:
                continue
            data = bytes.fromhex(h)
            mod = data[0]
            kc  = data[2]
            if kc == 0 or kc == prev:
                prev = kc; continue
            prev = kc
            ch = HID.get(kc)
            if ch is None:
                out.append(f"<{kc:02x}>"); continue
            if mod & 0x22:            # left/right shift
                ch = ch.upper() if ch.isalpha() else SHIFTED.get(ch, ch)
            out.append(ch)
    return "".join(out)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: usb-keystrokes.py caps.txt")
    print(decode(sys.argv[1]))


if __name__ == "__main__":
    main()
