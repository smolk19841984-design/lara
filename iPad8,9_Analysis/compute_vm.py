#!/usr/bin/env python3
vals = [18446744005107531776, 18446744005121458176, 18446744005107564544, 18446744005121458176, 18446744005161893888]
kb = 0xfffffff007004000
for v in vals:
    print(v, hex(v))
    print('signed:', v - (1<<64) if v & (1<<63) else v)
    print('v - kb =', hex((v - kb) & ((1<<64)-1)))
    print('')