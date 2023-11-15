// Run this script with
// frida -f test.exe -l frida_inject.js -- -f test\ok_input.txt

const moduleName = "test.exe"; // The module you want to hook
const functionName = "fuzz"; // The function you want to hook - On Windows' main is not exported
const dllPath = "frida_simple_exe.dll"; // Replace with your DLL path
const hookName = "main_hook"; // It is not really a hook, it accepts the real address of main
const hookSetterName = "set_fuzz_hook";//"set_main_hook"; 

// Find the module and function to hook
const targetModule = Process.getModuleByName(moduleName);
const mainOffset = 0x1200; // Replace with the offset of 'main'

// This function finds the base address of the module
function getModuleBaseAddress(moduleName) {
  return Module.findBaseAddress(moduleName);
}

function buf_to_hex(buffer) {
  const byteArray = new Uint8Array(buffer);
  const hexParts = [];
  for (let i = 0; i < byteArray.length; i++) {
      const hex = byteArray[i].toString(16);
      const paddedHex = ('00' + hex).slice(-2); // Pad with leading zeros
      hexParts.push(paddedHex);
  }
  return hexParts.join(' ');
}

function scope(address){
  const size = 16; // Number of bytes to dump
  const memory = Memory.readByteArray(address, size);
  send("Memory dump at " + address + " :\n " + buf_to_hex(memory));
  const instructions = Instruction.parse(address);
  send("Disassembly at " + address + " : " + instructions.toString());
}

function dumpObj(title, obj){
  send(title + ": " + obj);
  for (var prop in obj){
    send(prop + ": " + obj[prop]);
  }
}


// Calculate the absolute address
const baseAddress = getModuleBaseAddress(moduleName);
const mainAbsAddress = targetModule.findExportByName("main"); //baseAddress.add(mainOffset);
const fuzzFunction = targetModule.findExportByName(functionName);

send("Base Address: " + baseAddress);
send("Main Address: " + mainAbsAddress);
send("Fuzz Address: " + fuzzFunction);
send("Before hooking")
scope(mainAbsAddress)
scope(fuzzFunction)

// // Inject your DLL
const loadLibrary = new NativeFunction(Module.findExportByName("kernel32.dll", "LoadLibraryA"), 'pointer', ['pointer']);
const dllStr = Memory.allocUtf8String(dllPath);
var myLibAddr = loadLibrary(dllStr);
send("DLL loaded at " + myLibAddr);

// var myLibrary = Process.findModuleByAddress(myLibAddr)
// var myHook = myLibrary.findExportByName(hookName);    
// console.log("My hook at " + myHook);
// const mainHook = new NativeFunction(myHook, 'int', ['pointer']);

// Set the hook
// var myHookSetter = myLibrary.findExportByName(hookSetterName);
// send("My hook setter at " + myHookSetter);
// const mainHookSetter = new NativeFunction(myHookSetter, 'void', ['pointer']);
// mainHookSetter(mainAbsAddress);

// Attach to the main function using the absolute address
// Replace 'main' with your function from the DLL
// Interceptor.attach(mainAbsAddress, {
//   onEnter: function(args) {
//     var argc = args[0].toInt32();
//     var argv = args[1];

//     for (var i = 0; i < argc; i++) {
//         var argPtr = Memory.readPointer(argv.add(i * Process.pointerSize));
//         send('Argument[' + i + ']: ' + Memory.readUtf8String(argPtr));
//     }

//     send("Calling hook at " + myHook);
//     var hookRes = mainHook(mainAbsAddress);
//     send("Hook returned " + hookRes);
//   },
//   onLeave: function(retval) {
//   }
// });

send("After hooking")
scope(mainAbsAddress)
scope(fuzzFunction)

send("Script loaded")

// var mainThreadId = Process.enumerateThreads()[0].id; // Assuming the first thread is the main thread
// Process.enumerateThreads().forEach(function (thread) {
//   send(`Thread ID: ${thread.id}, State: ${thread.state}`);
//   if (thread.state == 'stopped'){
//     mainThreadId = thread.id;
//   }
// });

// send("Following " + mainThreadId)

// Stalker.follow(mainThreadId, {
//   transform: function (iterator) {
//       var instruction = iterator.next();
//       do {
//           iterator.putCallout(function (context) {
//               send('> ' + context.pc + ": " + Instruction.parse(context.pc));
//           });
//           iterator.keep();
//       } while (instruction = iterator.next());
//   }
// });

