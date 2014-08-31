                              CLU v0.0.8
                           Toorcon 8 Release



CLU is an IDA plugin that works with Tron to allow you to set invisible
software breakpoints. CLU is not enabled until you run it either via the 
plugin menu or with Alt-T. 

You can run Alt-T multiple times to recloak your window titles. Sometimes IDA
has a habit of closing windows it doesn't recognize when loading/unloading the
debugger. You can reopen them and then rerun CLU to recloak. Once CLU is
loaded, all software breakpoints will be hidden with Tron.

Microsoft's Detours-Express 2.1 is used by CLU due to limitations in IDA's
debugger plugin API. The license of detours allows for free redistribution of
the detours libs and header for non-commercial software, and are included.
CLU itself is public domain.



                             INSTALLATION

CLU requires the detoured.dll library to be copied into IDA's base install
directory. Copy clu.plw to your IDA plugins directory.

clu.plw was compiled with IDA 5.0's SDK. The sources are compatible with
the 4.9 SDK as well.

If you change your Tron nonce you must recompile CLU with the new header!


 - Alan Bradley <abradley@fastmail.fm>
