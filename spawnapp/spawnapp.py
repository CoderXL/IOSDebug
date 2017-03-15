#usage python spawnapp.py -U -f com.apple.weather
import codecs
import frida
import time, os, sys

identifier = ""
sleeptime = 3
gpid = 0
gargv = None

def on_message(message, data):
    global gpid
    print "received app up"
    gpid = message["payload"][1]
    os.system(" ".join(gargv) % gpid)

if __name__ == "__main__":
    host = None
    devtype = 0 # 1:usb  2:remote
    for index in range(0, len(sys.argv)):
        if sys.argv[index].find("-f") != -1:
            identifier = sys.argv[index + 1]
            gargv = sys.argv
            gargv[index] = "-p"
            gargv[index + 1] = "%d"
        elif sys.argv[index].find("-R") != -1:
            devtype = 2
        elif sys.argv[index].find("-U") != -1:
            devtype = 1
        elif sys.argv[index].find("-H") != -1:
            devtype = 2
            host = sys.argv[index + 1]
    if gargv is None:
        sys.exit(0)
    else:
        gargv[0] = "frida"

    # init script
    if devtype not in [1, 2]:
        sys.exit(0)
    if devtype == 1:
        curdev = frida.get_usb_device()
    else:
        curdev = frida.get_remote_device()

    launchd_session = curdev.attach(1)
    with codecs.open('launchd.js', 'r', 'utf-8') as f:
        source = f.read()
    launchd_script = launchd_session.create_script(source)
    launchd_script.on('message', on_message)
    launchd_script.load()

    kernel_session = curdev.attach(0)
    with codecs.open('kernel_task.js', 'r', 'utf-8') as f:
        source = f.read()
    kernel_script = kernel_session.create_script(source)
    kernel_script.load()

    # kill app first
    apps = curdev.enumerate_applications();
    for app in apps:
        if app.identifier == identifier and app.pid != 0:
            curdev.kill(app.pid)
            time.sleep(sleeptime)
            break

    # prepare to detect launch event
    launchd_script.exports.prepareforlaunch(identifier)
    # try launch
    kernel_script.exports.launchapp(identifier)

    time.sleep(20)
