# bacnet.py
Python module to parse hex-dump of BACnet Complex-ACK responses.

## Usage

Import the module and create a BACnet Reponse object with the reponse packet's hex-dump:

```
import bacnet

hex_dump = "810a0076010030160e0c020003e81e29384ea474080a034f29394eb404221e084f29464e750f004d4143482d50726f576562436f6d4f293a4e71004f294d4e7509004d4143482d50726f4f29784e21234f29794e751e0052656c6961626c6520436f6e74726f6c7320436f72706f726174696f6e4f1f"

response = bacnet.Response(hex_dump)
```


Then you have access to the BACnet fields:

```
for k, v in response.properties.items():
    print("Property ID: ", k, ", Property value: ", v)
```
