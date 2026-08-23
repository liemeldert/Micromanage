# Micromanage

Micromanage is an open source MDM platform for Apple devices. It aims to be simple to run and easy to extend.

Micromanage at its heart is built off of the NanoMDM project, and is designed to be an orchestration layer and interface
on top of their work.

I have spent a good deal of effort into getting things to the state they are now, however, I also am just one person. I
do not have the budget or time of a commercial team to dedicate to this project. I have already spent a decent amount of
my personal funds on testing devices and accounts to get things working. Micromanage is and will always be free and
open-source software with no expectation of payment. However, should you want to support me and this project, I have
a [Ko-fi page here](https://ko-fi.com/beomm) if you would like to donate, which I would dedicate to the continued
development of Micromanage including testing devices etc.

Micromanage began as a personal project a few years back because I was working for a team under leadership that was much
too cheap to pay for anything but the bare minimum number of licenses to cover in-use iPads.

This older iteration was based off of MicroMDM, which was helpful to give me an idea as to how an MDM should be
designed, but also felt like putting effort into a dead end.

While working on the original MicroMDM-based Micromanage version, I quickly began to notice how many little details in
the commercial MDM product we used bothered me, and turned me into the MDM version of discount Martin Luther leading me
to pinning my own 95 theses to JAMF's front door. They called the police on me after I broke a pane of glass on their
revolving door. <sub>may or may not be a true story</sub>
I built this project to get more familiar with MDM and to cosplay as a sysadmin at home; it is not a commercial product
or something I profit from. However, that said as someone that's been around school IT a lot, more affordable and
especially open-source options for device management are sorely needed. It's hard to justify the cost of a commercial
MDM solution for a small school where they only have a few hundred devices, and very few shared devices that someone
*could* just setup manually (but where's the fun in that).

Most of my time still goes into the project rather than the docs, because writing documentation is really boring.
[DEPLOY.md](DEPLOY.md) has some instructions on how to deploy Micromanage, but it is to provide a starting point for
your own deployment.

I am personally eating the Micromanage dog food by running all my personal Apple stuff on it, as well as a few testing
labs with VMs for development reasons. While so far it is running quite nicely, it does not mean there is a support
contract behind it. As such, I would not recommend using it for anything high stakes.

* I am not responsible for any damage or data loss that may occur from using this software. Use at your own risk.
* Should your iPhone turn into an evil dragon which then snatches your wig in front of someone you're trying to impress,
  I will not be here to provide emotional support or give you a new wig unless the story is particularly funny.
* I still eat my own dogfood. My roommate is not amused that our Apple TV randomly reset itself in the middle of an
  episode of Love Island.
* Read "What it does not do yet" before you use this for anything more important.

## What it does

* Over-the-air enrollment, with device identity certificates issued over SCEP by the bundled step-ca.
* Automated Device Enrollment (ADE/DEP) against Apple Business Manager or Apple School Manager.
* Declarative device management on the OS versions that support it.
* Profiles, apps, groups and tags, authored as YAML you can keep in git.
* App packages in S3, handed to devices as presigned manifests.
* Flows: a node editor for what happens to a device at enrollment.
* A compliance dispatcher that watches device state, remediates, and can POST a signed webhook.
* Break-glass escrow for managed admin, firmware and recovery lock passwords, and FileVault recovery keys.
    * Break-glass is a hidden secret that creates an obvious flag when it is used, similar to the mechanism in EPIC
* FileVault recovery key escrow: a per-tenant keypair, the escrow payload served beside any FileVault profile, and the
  key decrypted out of the device's SecurityInfo report. A rotate command re-keys a Mac whose current recovery key is
  escrowed or typed in; an already-encrypted Mac whose key nobody holds bootstraps with one local rotation (see
  DEPLOY.md).
* OS update enforcement over DDM
* Clear passcode on iPhone and iPad, using the UnlockToken read from NanoMDM's store.
* An audit log that keeps every admin action.
* Two roles, member and admin, split on who authors configuration.
* A REST API, and a CLI that talks to it.

## What it does not do yet

I plan to get to these in the future, but keep in mind we do not do these things yet.

* No VPP or App Store app assignment. App deployment is macOS `.pkg` only, so an iPad fleet gets no app management at
  all.
    * This should come soon; however, it is just a lot of work and cost on my end to test.
* OS update enforcement is DDM-only, so it needs macOS 14 or iOS 17 and later. There is no `ScheduleOSUpdate` fallback
  for older devices.
* Clear passcode is iPhone and iPad only. Apple's `ClearPasscode` is n/a on macOS and tvOS, so a Mac cannot have its
  FileVault or login password cleared this way.
* No bootstrap token handling and no Activation Lock bypass.
* No user channel. A user-channel enrollment gets an empty declaration set, so Shared iPad is not really managed.
* The enrollment profile is not frozen yet. Device identity certificates all share one subject per tenant, and the
  server capabilities the profile advertises are still changing. A device keeps working across upgrades, because the
  profile it already installed is the one it keeps using, but a device has to re-enroll to pick up changes made here.
  Worth knowing before you roll this out to a fleet you would not want to re-enroll by hand.
* No local daemon (yet), however, I plan to work on one soon. I have some existing work for a local daemon for macOS
  that handles app installations and updates more gracefully, so I could extend upon that work easily.
    * The daemon would also integrate JIT admin access, so users can stay at the minimum privilege level needed.
* Also, no local self-service app features yet.

### Some future integrations I would like to implement

These aren't in the app yet, however, are things I would like to implement in the future and would be able to do easily
with what I own.

* Unifi integration
    * Unifi has a REST API that can be used for visibility on devices and clients, so we could integrate some
      information like getting device AP, site locations based off that, etc etc
* Tailscale integration
    * Tailscale has a lot of features that I think could be used for remote triage without needing to worry about
      certain firewall rules or security implications.
        * I think the daemon would also be able to integrate with the Tailscale daemon as well, to colect some extra
          stats
        * The compliance and flows system could integrate nicely to allow/disallow connection to privilaged services
          based on device posture etc.
        * there is existing device posture support in tailscale for some commercial VPNs
* Ansible integration
    * Ansible is a great tool for automating things, so with a Tailscale integration as well, we could have providers to
      create inventories etc automatically

## Requirements for app packages

macOS installs packages (`InstallApplication` with a manifest URL) only when it is a product archive:
build it with `productbuild` and sign it with a Developer ID Installer certificate.

At the moment, packages have to be signed and silently fail if not. Soon I plan to add better checks overall for apps.

## Micromanage IAC Controller

* At the center of Micromanage is the IAC controller.
* This parses YAML configuration files with expected state for devices and attempts to bring the devices into that
  state.
* Devices are managed declaratively, so the same YAML fits into an existing CI/CD pipeline.
* Keeping configuration in version control makes rollback and incremental changes straightforward.
* Past the basic profile/app/group management, it also handles zero-touch enrollment through Apple Business/School
  Manager (DEP/ADE), Apple's newer declarative device management (DDM) on OS versions that support it, a small
  node-based flow editor for scripting what happens at enrollment (tag the device, install stuff, wait for it to check
  in, branch on OS version), and a compliance/dispatcher layer that watches for things like FileVault being off or a
  device going into Lost Mode and can auto-remediate or fire a webhook.

## Micromanage WebUI

The WebUI is based on Next.JS and Mantine. By default, the WebUI hides the YAML configuration given to the IAC
controller, however, has a toggle in settings to enable it. I decided on that until I could get a better idea of how
YAML configuration errors could manifest themselves on the actual devices.

## Deployment

See [DEPLOY.md](DEPLOY.md) for deployment instructions, including backup, restore and upgrades. However, please do note
that obtaining the actual MDM push certificate from Apple is difficult and relatively expensive, as it needs a Vendor
CSR. I have access to the necessary resources so I might be able to see what I can do to help provide *something* to
interested users. However, I won't guarantee anything since I want to make sure I stay within Apple's rules. They don't
seem to be particularly fond of an MDM outside of business or education uses.

I'm also working on a little hosted version of Micromanage, but this is nowhere near ready for public use. In the
future, I plan to slowly roll out the hosted version to people that are interested in testing it out.

