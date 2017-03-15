var dlopen;
var dlsym;
var kill;
var SBSLaunchApplication;
var DeviceKey;
var NSString;
var NSDictionary;

rpc.exports = {
  launchapp: function (identifier) {
    ObjC.schedule(ObjC.mainQueue, function () {
        var bundle = strJsToNs(identifier);
        var options = NSDictionary.dictionaryWithObject_forKey_(1, DeviceKey);
        SBSLaunchApplication(bundle, ptr("0"), ptr("0"), options, 0);
    });
  },
};

var priframedir = "/System/Library/PrivateFrameworks/";
var springboardservice = priframedir + "/SpringBoardServices.framework/SpringBoardServices";

function strJsToNp(jsstr){
	return Memory.allocUtf8String(jsstr);
}

function strJsToNs(jsstr){//run in mainQueue
	return NSString.stringWithUTF8String_(Memory.allocUtf8String(jsstr));
}

function init(){
    var np;
    np = Module.findExportByName(null, "dlopen");
    dlopen = new NativeFunction(np, "pointer", ["pointer", "int"]);
    np = Module.findExportByName(null, "dlsym");
    dlsym = new NativeFunction(np, "pointer", ["pointer", "pointer"]);
    np = Module.findExportByName(null, "kill");
    kill = new NativeFunction(np, "int", ["int", "int"]);
    var sbServices = dlopen(strJsToNp(springboardservice), 1);
    np = dlsym(sbServices, strJsToNp("SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions"));
    SBSLaunchApplication = new NativeFunction(np, "int",
        ["pointer", "pointer", "pointer", "pointer", "int"]);
    np = dlsym(sbServices, strJsToNp("SBSApplicationLaunchOptionUnlockDeviceKey"));
    DeviceKey = Memory.readPointer(np);

    //after dylib load we can use NS_cla
    NSString = ObjC.classes.NSString;
    NSDictionary = ObjC.classes.NSDictionary;
}

init();
console.log("kernel_task init ok");