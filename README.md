### AEON-Stak-CPU - AEON mining software (fork of fireice-uk/xmr-stak-cpu) with AEON and customizable low power mode

**This fork changes it for AEON and makes `low_power` mode customizable. This mode will solve X hashes per thread. Change the values in `crypto/cryptonight_aesni.h` and `minethd.cpp`. Default is 2.**

It may become a PR and get merged back to upstream if the original one wants AEON support.

**This fork won't GPG sign Windows binaries as they are built automatically by AppVeyor CI and I have no Windows Machine**

## HTML reports
<img src="https://gist.githubusercontent.com/fireice-uk/2da301131ac01695ff79539a27b81d68/raw/4c09cdeee86f94df2e9dd86b927e64aded6184f5/xmr-stak-cpu-hashrate.png" width="260"> <img src="https://gist.githubusercontent.com/fireice-uk/2da301131ac01695ff79539a27b81d68/raw/4c09cdeee86f94df2e9dd86b927e64aded6184f5/xmr-stak-cpu-results.png" width="260"> <img src="https://gist.githubusercontent.com/fireice-uk/2da301131ac01695ff79539a27b81d68/raw/4c09cdeee86f94df2e9dd86b927e64aded6184f5/xmr-stak-cpu-connection.png" width="260">

## HTML and JSON API report configuraton

To configure the reports shown above you need to edit the httpd_port variable. Then enable wifi on your phone and navigate to [miner ip address]:[httpd_port] in your phone browser. If you want to use the data in scripts, you can get the JSON version of the data at url [miner ip address]:[httpd_port]/api.json

## Usage on Windows 
1) Edit the config.txt file to enter your pool login and password. 
2) Double click the exe file. 

XMR-Stak should compile on any C++11 compliant compiler.
## Compile guides

- [Free BSD](FREEBSDCOMPILE.md)
- [Linux](LINUXCOMPILE.md)
- [Windows](WINCOMPILE.md)


#### CPU mining performance 

* **E5-2630 v1** - 1040 H/s

## Default dev donation
By default the miner will donate 2% of the hashpower (2 minute in 100 minutes) to my pool. If you want to change that, edit **donate-level.h** before you build the binaries.

If you want to donate directly to support this **AEON FORK**:

fireice-uk:
```
AEON WALLET
Wmt4c5SLGAE9QjeN7B2nt9i2XRegisu96af24VqhKMa53yDZjGui14bMYQK2WaQyj6D3GqndgVk4hMEbSSxdUSSv2qyygU83e
```

=======
If you want to donate directly to support further development, here is **fireice-uk XMR wallet**

```
XMR WALLET (fireice-uk)
4581HhZkQHgZrZjKeCfCJxZff9E3xCgHGF25zABZz7oR71TnbbgiS7sK9jveE6Dx6uMs2LwszDuvQJgRZQotdpHt1fTdDhk
XMR WALLER (psychocrypt)
43NoJVEXo21hGZ6tDG6Z3g4qimiGdJPE6GRxAmiWwm26gwr62Lqo7zRiCJFSBmbkwTGNuuES9ES5TgaVHceuYc4Y75txCTU
```

## Common Issues

**SeLockMemoryPrivilege failed**

Please see [config.txt](config.txt) under section **LARGE PAGE SUPPORT**

For Windows 7 pro, or Windows 8 and above see [this article](https://msdn.microsoft.com/en-gb/library/ms190730.aspx)  (make sure to reboot afterwards!).

For Windows 7 Home :

1) Download and install [Windows Server 2003 Resource Kit Tools](https://www.microsoft.com/en-us/download/details.aspx?id=17657).  Ignore incompatiablity warning during installation.

2) In cmd or power shell: `ntrights -u %USERNAME% +r SeLockMemoryPrivilege`  (where %USERNAME% is the user that will be running the program.  This command needs to be run as admin)

3) Reboot.

Reference: http://rybkaforum.net/cgi-bin/rybkaforum/topic_show.pl?pid=259791#pid259791

*Warning: do not download ntrights.exe from any other site other then the offical Microsoft download page.*

**VirtualAlloc failed**

If you set up the user rights properly (see above), and your system has 4-8GB of RAM (50%+ use), there is a significant chance that there simply won't be a large enough chunk of contiguous memory because Windows is fairly bad at mitigating memory fragmentation.

If that happens, disable all auto-staring applications and run the miner after a reboot.

**msvcp140.dll and vcruntime140.dll not available errors**

Download and install this [runtime package](https://go.microsoft.com/fwlink/?LinkId=746572) from Microsoft.  *Warning: Do NOT use "missing dll" sites - dll's are exe files with another name, and it is a fairly safe bet that any dll on a shady site like that will be trojaned.  Please download offical runtimes from Microsoft above.*


**Error: MEMORY ALLOC FAILED: mmap failed**

From [config.txt](config.txt):

On Linux you will need to configure large page support `sudo sysctl -w vm.nr_hugepages=128` and increase your
ulimit -l. To do do this you need to add following lines to /etc/security/limits.conf:

    * soft memlock 262144
    * hard memlock 262144
    
Save file.  You WILL need to log out and log back in for these settings to take affect on your user (no need to reboot, just relogin in your session).
   
You can also do it Windows-style and simply run-as-root, but this is NOT recommended for security reasons.

**Illegal instruction (core dumped)**

This typically means you are trying to run it on a CPU that does not have [AES](https://en.wikipedia.org/wiki/AES_instruction_set).  This only happens on older version of miner, new version gives better error message (but still wont' work since your CPU doesn't support the required instructions).


## Advanced Compile Options

The build system is CMake, if you are not familiar with CMake you can learn more [here](https://cmake.org/runningcmake/).

### Short Description

There are two easy ways to set variables for `cmake` to configure *aeon-stak-cpu*
- use the ncurses GUI
  - `ccmake .`
  - edit your options
  - end the GUI by pressing the key `c`(create) and than `g`(generate)
- set Options on the command line
  - enable a option: `cmake . -DNAME_OF_THE_OPTION=ON`
  - disable a option `cmake . -DNAME_OF_THE_OPTION=OFF`
  - set a value `cmake . -DNAME_OF_THE_OPTION=value`

After the configuration you need to call
`make install` for slow sequential build
or
`make -j install` for faster parallel build
and install.

### aeon-stak-cpu Compile Options
- `CMAKE_INSTALL_PREFIX` install miner to the home folder
  - `cmake . -DCMAKE_INSTALL_PREFIX=$HOME/aeon-stak-cpu`
  - you can find the binary and the `config.txt` file after `make install` in `$HOME/aeon-stak-cpu/bin`
- `CMAKE_LINK_STATIC` link libgcc and libstdc++ libraries static (default OFF)
  - disable with `cmake . -DCMAKE_LINK_STATIC=ON`
-`CMAKE_BUILD_TYPE` set the build type
  - valid options: `Release` or `Debug`
  - you should always keep `Release` for your productive miners
- `MICROHTTPD_ENABLE` allow to disable/enable the dependency *microhttpd*
  - by default enabled
  - there is no *http* interface available if option is disabled: `cmake . -DMICROHTTPD_ENABLE=OFF`
- `OpenSSL_ENABLE` allow to disable/enable the dependency *OpenSSL*
  - by default enabled
  - it is not possible to connect to a *https* secured pool if option is disabled: `cmake . -DOpenSSL_ENABLE=OFF`
- `HWLOC_ENABLE` allow to disable/enable the dependency *hwloc*
  - by default enabled
  - the config suggestion is not optimal if option is disabled: `cmake . -DHWLOC_ENABLE=OFF`
