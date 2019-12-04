# Privilege Escalation Checklist

*keep in mind that these notes are intended to provides a little and really basic checklist that I could sometimes follow when I feel stuck on scenario(s) like CTFs.*

----
## What do I have in my hands?
1. Analyze every single information you found until now such as hosts, services, webroot, credentials, users..


----
## Basically what should I try?
0. Have you a doubt? Use always Google to clarify and try to go always a bit more in depth
1. Check kernel/OS version and installed patches
2. Check user permissions
3. Check about services
4. Read all configuration files
5. Process monitoring
6. Read the version all programs that are installed
7. Sniffing?
8. Seek files and try to understand which can contain useful information and collect them
9. Keep notes of everything you find interesting and be curious.

> If you are playing a CTF you could think that are not active users: remember that they could be there and they could be active as fuck

----
## Which resources could become useful?
0. Google is always the best resource to search up to date information to exploit
1. [Linenum](https://github.com/rebootuser/LinEnum) or [JAWS](https://github.com/411Hall/JAWS)
2. [Linux exploit suggester](https://github.com/mzet-/linux-exploit-suggester) or [Windows exploit suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
3. [PSPY](https://github.com/DominicBreuker/pspy) or procmon.sh
    
        #!/bin/bash
        prev_proc=$(ps -eo command)
        while true; do
            current_proc=$(ps -eo command)
            diff <(echo "$prev_proc") <(echo "$current_proc")
            sleep 1
            prev_proc=$current_proc
        done

4. [GTFOBINS](https://gtfobins.github.io/) or [LOLBAS](https://lolbas-project.github.io/)
5. [ippsec](https://ippsec.rocks/)?

> Keep in mind that these are just tools, so you have to use your mind and you have to execute each step manually: don't trust tools.

----
## I feel stuck really stuck, what to do?
0. Keep a little pause and think about what you found until this moment
1. Repeat enumeration steps
2. Try to go more in depth
3. Try harder!

> We can learn everyday a new concept, nobody knows everything.
> We will be always noobs!
