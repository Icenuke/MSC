# MalwareSigChecker *(MSC)*
## Description:
> This script check all files to see if is present in blacklist<br>
> The blacklist must contain the hash of files. (md5/sha1/sha256)<br>
> The file can be check with VirusTotal with the API.<br>
> A Whitelist can be generated.<br>
## How to install:
> Download the script<br>
> Add hash in bllaclist file<br>
## How to use:
> Usage: MSC [ -h | -hl | -md5 | -sha1 | -sha256 | -vt | -b <BlackList> ] <Path2Check><br>
> Options:<br>
> -h 				Show this message<br>
> -hl 			Generate a Hashlist of all file in system, md5.txt, sha1.txt, sha256.txt<br>
> -md5 			Precise the hashes contain in blacklist are md5<br
> -sha1 			Precise the hashes contain in blacklist are sha1<br>
> -sha256			Precise the hashes contain in blacklist are sha256<br>
> -vt 			Hash all file and check in VirusTotal, Add the vt api key in vt.conf<br>
> -b <blacklist>	The file which contain the hash (md5 or sha1 or sha256)<br>
