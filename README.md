# Using wireshark to capture and analyse log files for Auerswald PBX systems

This repository contains the files and information to use Wireshark instead of the legacy "D-Kanal Logger".
For Wireshark to display data in the auerswald pcap logger format, the corresponding protocol dissector must be installed.

## Installation

* Install a current version of Wireshark (see "Wireshark Log Format" below)
* Download the Wireshark protocol dissector ```auerlog.lua``` from this repository
* Copy ```auerlog.lua``` to your "Personal Plugins" directory for Wireshark, which can be found under "Help" -> "About Wireshark" -> "Folders" -> "Personal Plugins".
* Select "Analyze" -> "Reload Lua Plugins" (Ctrl+Shft+L)

On a Linux system check for the right folder and then copy the ```auerlog.lua``` file to it.
Depending on your OS and version of Wireshark
```~/.config/wireshark/plugins```
or
```~/.local/lib/wireshark/plugins``` would be popular places.
If the directory doesn't exist, create it.

## Remote Logging Ports

If remote logging is activated within a supported Auerswald PBX, the daemon opens 1 or 2 TCP ports as server:

* 42225 Used by the previous DKanal tool (if this is the only port open, you can stop reading here)
* 42231 Used for logging with nc, wireshark or tshark (PCAP stream)

## Recording a "DKanal" style pcap trace log

The following examples assume that you want to record a log for an Auerswald PBX with the IP address **192.168.22.51**.
You have to **replace this IP address** in the examples with the **IP address of your Auerswald PBX**:

### Linux commandline capture

Logging to a file is very easy with the netcat tool:

```bash
nc 192.168.22.51 42231 > log.pcap
```

Netcat (nc) is a tool found on most linux systems. It does not need a gui and recording trace logs with nc uses very little resources and does not require Wireshark to be installed.
The resulting file can later be opened and analyzed with Wireshark.

## Live Capture with Wireshark

You can however also capture the trace log with Wireshark directly, and display it at the same time:

### Linux Live Capture

Starting Wireshark with the following command will start logging right away.

```bash
wireshark -k -i TCP@192.168.22.51:42231 &
```

If needed a shortcut can be created.
Use the "start capturing", "stop capturing" and "save" functions of Wireshark to record the logs you need.

### Windows

Create a shortcut to the Wireshark binary and add the command line arguments starting with "-k ..." so the "Target" looks similar to this:

```cmd
"C:\Program Files\Wireshark\Wireshark.exe" -k -i TCP@192.168.22.51:42231
```

Clicking the prepared shortcut link is usually something that everyone can do and starts logging instantly.
Use the "start capturing", "stop capturing" and "save" functions of Wireshark to record the logs you need.

## Recording a combined log with Wireshark

You can create a combined "D-Kanal" style trace and a network log by specifying multiple sources. e.g.

```bash
wireshark -k -i TCP@192.168.22.51:42231 -i eth0 &
```

If you want to create a combined network and trace log you will need to have Wireshark with the non-root capture options installed. Use google to find out, if you are unsure on how to do this.
Under Linux remember that your user has to be a member of the ''wireshark'' group.
To add your user to that group use ''sudo usermod -a -G wireshark $USER''.
The change will only take effect after your next login.
Also note, your network interface might not be named ''eth0'' but something much longer like ''enx00e04d6711e1'', change the name accordingly. You can specify multiple interfaces by adding further ''-i *devicename*'' options.
If you are not sure which interface to log, or what their names are, you can start Wireshark without the ''-k'' option and manually select the interfaces to log at startup.

```bash
wireshark -i TCP@192.168.22.51:42231
```

## Wireshark Log Format

The messages within the pcap are either provided in the old format which uses the **DLT_USER0** (147) or in the new format which uses the **DLT_AUERSWALD_LOG** (296) and temporarily **DLT_USER1** (148).
All three DLT IDs are supported by the same dissector script.

We received DLT_AUERSWALD_LOG and LINKTYPE_AUERSWALD_LOG on Sept 2. 2022 with the DLT ID 296, it will be a while before the libpcap update is populated everywhere.
So far only the latest Wireshark branch 4.1 contains support for DLT_AUERSWALD_LOG.
As of March 2023 you still need the latest Wireshark developer version to dissect logfiles using the DLT_AUERSWALD_LOG.
Which is the reason why we still use DLT_USER0 and DLT_USER1 in official software releases. However developer or diagnostic builds may contain the DLT_AUERSWALD_LOG.
Wireshark Developer builds for Windows and OSx can be found on <https://www.wireshark.org/download/automated/>

The description for the DLT_AUERSWALD_LOG log format is publicly released and can be found on <https://github.com/Auerswald-GmbH/auerlog/blob/master/auerlog.txt>

***
