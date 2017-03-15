var dlopen;
var dlsym;
var SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions;
var SBSApplicationLaunchOptionUnlockDeviceKey;
var NSString;

rpc.exports = {
  launchApp: function (identifier) {
    specidentifier = identifier;
  },
  killApp: function (identifier) {
    specidentifier = null;
  }
};

var priframedir = "/System/Library/PrivateFrameworks/";
var springboardservice = priframedir + "/SpringBoardServices.framework/SpringBoardServices";

function strJsToNp(jsstr){
	return Memory.allocUtf8String(jsstr);
}

function strJsToNs(jsstr){
	return NSString.stringWithUTF8String_(Memory.allocUtf8String(jsstr));
}

function init(){
    var np;
    np = Module.findExportByName(null, "dlopen");
    dlopen = new NativeFunction(np, "pointer", ["pointer", "int"]);
    np = Module.findExportByName(null, "dlsym");
    dlsym = new NativeFunction(np, "pointer", ["pointer", "pointer"]);
    var sbServices = dlopen(strJsToNp(springboardservice), 1);
    np = dlsym(sbServices, strJsToNp("SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions"));
    SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions = new NativeFunction(np, "int",
        ["pointer", "pointer", "pointer", "pointer", "int"]);
    np = dlsym(sbServices, strJsToNp("SBSApplicationLaunchOptionUnlockDeviceKey"));
    SBSApplicationLaunchOptionUnlockDeviceKey = Memory.readPointer(np);

    //after dylib load we can use NSString
    NSString = ObjC.classes.NSString;
}




/*
ObjC.schedule(ObjC.mainQueue, function () {
	var bundle = strJsToNs("com.apple.calculator");
	SBSLaunchApplicationWithIdentifier(bundle, 0);
	//SBSLaunchApplicationWithIdentifierAndLaunchOptions(bundle, ptr("0"), 0);
	//SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions(bundle, ptr("0"), ptr("0"), ptr("0"), 0);
	console.log("spawn");
});
*/


Interceptor.replace(
	dlsym(sbServices, strJsToNp("SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions")),
	new NativeCallback(function(id,url,param,option,suspend){
		console.log(ObjC.Object(option).toString());
		var bundle = strJsToNs("com.apple.calculator");
		send("ok");
		return 0;
		//return SBSLaunchApplicationWithIdentifier(bundle, 0);
	}, "int", ["pointer", "pointer", "pointer", "pointer", "int"])
);


