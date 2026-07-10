# Micromanage

Micromanage is an open source MDM platform for Apple devices. It is designed to be simple, flexible, and extensible.
Micromanage at its heart is built off of the NanoMDM project, and is designed to be a orchistration layer and interface on top of their work.
Micromanage began as a personal project a few years back because I was working for a team under leadership that was much too cheap to pay for anything but the bare minimum number of licenses to cover in-use iPads. 
This was based off of MicroMDM, which was helpful to give me an idea as to how an MDM should be designed, but also felt like putting effort into a dead end.
While working on the original MicroMDM-based Micromanage version, I quickly began to notice how many little details in the commercial MDM product we used bothered me, and turned me into the MDM version of discount Martin Luther leading me to pinning my own 95 theses to JAMF's front door. They called the police on me after I broke a pane of glass on their revolving door. <sub>may or may not be a true story</sub>
This project was not made to be a commercial product nor be something I profit off of, but rather something that to get myself more familiar with MDM as well as cosplay as a sysadmin at home.
However, that said as somoene that's been around school IT a lot, more affordable and especially open-source options for device management are sorely needed.
It's hard to justify the cost of a commercial MDM solution for a small school where they only have a few hundred devices, and very few shared devices that someone *could* just setup manually (but where's the fun in that).

At the moment, I'm spending most of my time working on the actual project over documentation, so it is not particularly helpful.
Sadly writing documentation is really boring.

**This project is in early development, and is not yet ready for production use.**
I am not responsible for any damage or data loss that may occur from using this software. Use at your own risk.
Should your iPhone turn into an evil dragon which then snatches your wig in front of someone you're trying to impress, I will not be here to provide emotional support or give you a new wig unless the story is particularly funny.
That said, I'm testing it in a few really random environments to force myself to eat my own dogfood. My roommate is not amused that our Apple TV randomly reset itself in the middle of an episode of Love Island.

## Micromanage IAC Controller

At the center of Micromanage is its IAC controller.
This parses YAML configuration files with expected state for devices and attempts to bring the devices into that state.
This design means that Micromanage can be used to manage devices in a declarative way, and can be integrated into existing CI/CD pipelines.
Another benefit of this design is that it dramatically simplifies version control of configurations, allowing for easy rollback and incremental application of changes.

## Micromanage WebUI

The WebUI is based on Next.JS and Mantine. By default, the WebUI hides the YAML configuration given to the IAC controller, however, has a toggle in settings to enable it.
I decided on that until I could get a better idea of how YAML configuration errors could manifest themselves on the actual devices.

## Deployment

For now, see [DEPLOY.md](DEPLOY.md) for deployment instructions. It is not particularly helpful, but I plan to get to writing more complete documentation eventually.
However, please do note that obtaining the actual MDM push certificate from Apple is difficult and relatively expensive, as it needs a Vendor CSR. I have access to the necessary resources so I might be able to see what I can do to help provide *something* to interested users. However, I won't guarentee anything since I want to make sure I stay within Apple's rules. They don't seem to be particularly fond of an MDM outside of buisness or education uses.

I'm also working on a little hosted version of Micromanage, but this is nowhere near ready for public use.
In the future, I plan to slowly roll out the hosted version to a few *homelab/residential users only* to get some low-stakes.
