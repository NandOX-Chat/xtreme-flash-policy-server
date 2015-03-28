# Xtreme Flash Policy Server

----------------------------------
What's Xtreme Flash Policy Server?
----------------------------------

It's an Adobe Flash cross-domain-policy file socket delivering server focused (but not limited to) on IRC environments.

Although it's designed to be used in conjunction with LightIRC (http://www.lightirc.com/) it's suitable for many other
environments which needs to serve cross-domain-policy files through network as long as meets Adobe specifications
(more info about Adobe cross-domain-policy: http://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html).

Xtreme Flash Policy Server includes some additional useful features (optionals):

* Three peer connection pool methods: QUEUE, FORK and THREAD.
* Flood connect protection by using max-conn and time thresholds (detect and blacklist).
* IRC Bot to monitor service activity.
* !Fantasy commands for IRCops to interact with IRC Bot.
* Logging activity to a file (server-side).

--------------------
INSTALL INSTRUCTIONS
--------------------

Our goal is you can run this software out of the box, however, it may be a good idea to take a look the documentation before at:

[English] http://www.nandox.com/en/xtreme-flash-policy/

[Spanish] http://www.nandox.com/xtreme-flash-policy/

The NandOX IRC Chat Network Development Team

------------------
CHANGELOG/VERSIONS
------------------

Legend
-------
 + = New feature.
 - = Removed feature (deprecated or replaced by a better one).
 * = Improved, changed or updated feature.
 ! = Bug fixed (I hope)

Thanks to people who has been contributed to testing, sending suggestions and reporting bugs (they are mentioned where corresponding)

Version 1.1.1 (released at 28-03-2015)
------------------------------------

 - Code revision upgrade.

Version 1.1 (released at 11-01-2012)
------------------------------------

 + Added Flood Connection Protection. IP based flood protection by amound of peer connections attempts in a
   predefined lapse of time (thresholds). If a client is blacklisted its connections will be dropped automatically while expires 
   penalty. Option to execute external command or script is available.

 + Added POLICY_PEERPOOLMETHOD to define client connection pool method: QUEUE, FORK or THREAD 
   depending your needs and/or posibilities, or whether you want to play with finetuning and/or benchmarking.
   Each method has pros and cons (damn!):

    QUEUE: Handles connections by peer-connect queue. Queue size is defined by POLICY_CONNQUEUE and works flawless but
           gives no isolation (It may -or don't- be important depending on how paranoid you are). This method consumes very low
           resources in comparision with FORK and THREAD.

     FORK: Handles connections by fork() (sub-processes). I have a very good results on testing using forking even
           knowing they are slow to create and everything in memory is cloned resulting in a bit more memory consumption.
           Isolation is present with FORK.

   THREAD: Handles connections by thread. It's supposed to be the best method (fast to create and lower memory consumption), also
           isolation is present. However in my own testings I see a best performance on FORK method, but not THREAD.
           If you choose THREAD consider that you may experience some memory leak depending version of Perl you have: It's suppossed 
           to be fixed since version 5.13.5 (https://rt.perl.org/rt3/Public/Bug/Display.html?id=69598) 
           it's a Perl issue, but not Xtreme Flash Policy.

   Choose the method which better fits your needs. Play yoursefl!

 + Added IRC stats avaliable by "!policy stats" to show some usefull system info at IRCops channel room.

 * Added !policy prefix configuration by settings IRC_FANTASY_PREFIX if you want to personalize !fantasy trigger.

 + Added POLICY_PORT_FALLBACK. Default port for Adobe cross-domain-policy service is 843, but as you known (I think so!) any port
   below 1024 requires root privileges. If the default port (POLICY_PORT) is unaccesible Xtreme Flash Policy will use fallback
   POLICY_PORT_FALLBACK setted by default at port 8002. (suggested by Valentin Manthei)

 * Dropped usage of external modules (IO::File, File::Pid, IO::Select, etc) now everything is coded
   with low-level routines and out-of-the-box Perl's functions (provided by perl and perl-core-modules packages) 
   due many people don't be able to install external packages in their shell accounts. It makes 
   Xtreme Flash Policy more portable and suitable on different sceneries. (suggested by Valentin Manthei)

 - Removed option for die if root checking enabled and running Xtreme Flash Policy as root (LOOK_ROOTNOTICE), instead
   LOOK_ROOTNOTICE option was added for, if enabled only send a notice about security risk without exit.

 ! Fixed many bugs in regexps at IRC Bot feature. (tested and reported by Pablorrr)

 ! Fixed bug in constants POLICY_ALLOW_HOST and POLICY_ALLOW_PORT. (reported by Valentin Manthei)

 + Configuration out of the main code. Now config is located at config.pm file so you would't 
   reconfigure everything again in a future released version.

 * Many others general code improvements.

Version 1.0 (released at 10-18-2012)
------------------------------------
 + First release (Policy agent, IRC Bot agent, Log agent) with thread capabilities.
