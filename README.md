# zte_ussd

Send USSD codes through a ZTE MF79U USB modem, so the SIM card can stay where it is.

It speaks the same HTTP API as the modem's web interface. One Python 3 file, no dependencies.

## Usage

```
python3 zte_ussd.py info               modem and network status
python3 zte_ussd.py send "*100#"       send a USSD code, menus are answered interactively
python3 zte_ussd.py shell              interactive USSD session
python3 zte_ussd.py sms 1234 "hello"   send an SMS
```

You are asked for the password of the web interface. Use `--host` if the modem is not at 192.168.0.1 and `-v` to see the HTTP traffic.

## USSD fails right away

On LTE the modem drops USSD requests at once. Disconnect in the web interface, set the network mode to 2G, send your code, then switch back.

## Tested with

ZTE MF79U, firmware BD_XCBZHKMF79UV1.0.0B03. Other ZTE modems with the same web interface may work.

## Tests

```
python3 -m unittest discover -s tests
```

## Credits

Login and checksum details were checked against [mf79u-gsm-gateway](https://github.com/kerabann/mf79u-gsm-gateway) and [zte-mf79u-telegram-sms-relay](https://github.com/ijwfly/zte-mf79u-telegram-sms-relay).

## License

MIT
