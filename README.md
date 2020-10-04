# SMC-Toolkit
Toolkit written in Python for working with Apple SMC Payloads. Generates complete firmware files from payload components. Intended for 2013+ systems that utilize the 4 part smc updates (flasher_base, flasher_update, epm, Mac-Board-ID).

__Usage:__
```
reconstruct.py <base path to firmware payloads>
```

__Example:__
```
reconstruct.py SMCPayloads/10.15.6/Mac-B4831CEBD52A0C4C
```

`reconstruct.py` will strip payload chunks by address block and store them individually in a folder entitled `extracted` in the same location as `reconstruct.py`. It will then take those chunks and build the firmware file and save it in `extracted/firmware`.
