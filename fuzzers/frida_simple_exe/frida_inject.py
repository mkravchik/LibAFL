import frida
import sys

moduleName = "test.exe"; # The module you want to hook
dllPath = "frida_simple_exe.dll"; 
hookName = "main_hook"; # It is not really a hook, it accepts the real address of main


ss = """
const moduleName = "test.exe"; // The module you want to hook
const dllPath = "frida_simple_exe.dll"; // Replace with your DLL path
const hookName = "main_hook"; // It is not really a hook, it accepts the real address of main

// Find the module and function to hook
const targetModule = Process.getModuleByName(moduleName);
//const targetFunction = targetModule.findExportByName(functionName);
const mainOffset = 0x1200; // Replace with the offset of 'main'

// This function finds the base address of the module
function getModuleBaseAddress(moduleName) {
  return Module.findBaseAddress(moduleName);
}

// Calculate the absolute address
const baseAddress = getModuleBaseAddress(moduleName);
const mainAbsAddress = baseAddress.add(mainOffset);

console.log("Base Address: " + baseAddress);
console.log("Main Address: " + mainAbsAddress);

// Print the state of all threads
var threads = Process.enumerateThreads();
threads.forEach(function (thread) {
    console.log('Thread ID:', thread.id, 'State:', thread.state);
});

// // Inject your DLL
const loadLibrary = new NativeFunction(Module.findExportByName("kernel32.dll", "LoadLibraryA"), 'pointer', ['pointer']);
const dllStr = Memory.allocUtf8String(dllPath);
var myLibAddr = loadLibrary(dllStr);
console.log("DLL loaded at " + myLibAddr);
var myLibrary = Process.findModuleByAddress(myLibAddr)
console.log("myLibrary", myLibrary);
var myHook = myLibrary.findExportByName(hookName);    
console.log("My hook at " + myHook);

const mainHook = new NativeFunction(myHook, 'int', ['pointer']);

console.log("Calling hook at " + myHook);
var hookRes = mainHook(mainAbsAddress);
console.log("Hook returned " + hookRes);

Interceptor.attach(mainAbsAddress, {
  onEnter: function(args) {

    var argc = args[0].toInt32();
    var argv = args[1];

    for (var i = 0; i < argc; i++) {
        var argPtr = Memory.readPointer(argv.add(i * Process.pointerSize));
        console.log('Argument[' + i + ']: ' + Memory.readUtf8String(argPtr));
    }
  },
  onLeave: function(retval) {
    console.log("onLeave");    
    // If you chose to call the original 'main'
    // if (this.callOriginal) {
    //   // Code to handle after original 'main' execution
    // }
  }
});
"""

device = frida.get_local_device()
pid = device.spawn("test.exe", argv=["test.exe","-f", "test\\ok_input.txt"])
session = device.attach(pid)
script = session.create_script(ss)
script.load()
device.resume(pid)

