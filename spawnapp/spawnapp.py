import codecs
import frida
import time

def on_message(message, data):
    print(message)

launchd_session = frida.get_usb_device().attach(1)
with codecs.open('launchd.js', 'r', 'utf-8') as f:
    source = f.read()
launchd_script = launchd_session.create_script(source)
launchd_script.on('message', on_message)
launchd_script.load()
time.sleep(10)