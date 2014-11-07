Graylog2
========

Graylog2-Fabric is script based on Fabric Python Library writed to deploy and
configure a software stack based on Graylog2, Graylog2-Web, Elastic Search and
Mongo DB. This installation script will perform an automated install of Graylog2 
on Ubuntu 12.04/12.10/13.10/14.04


Version
----

1.0

Tested And Working On:


Ubuntu 12.04.4 LTS (GNU/Linux i686)


Tech
-----------

Graylog2-Fabric uses a number of projects to work properly:

* [Graylog2] - An integrated log capture and analysis solution 
* [Graylog2-Web] - A web Server Interface to Graylog2 for Linux
* [Elasticsearch] - Open source, distributed, real-time search and analytics engine
* [Mongo DB] - NoSQL Database
* [Fabric] - Python Library 
* [Fabtools] - Fabric Modules Extension


Installation
--------------
sudo apt-get install python-pip build-essential python-dev
sudo pip install fabric fabtools pwgen pymongo 



the default value is "localhost" but it can be changed according to your system with a public or private IP address. 


Execute
--------------

$ fab deploy


you will be asked for the ip and your sudo passwd.
The script has actually some additional logging functions
which can be deactivated or incremented as you want.


Post Installation
-------------
Open Your Browser on http://IP:9000 and login with user: admin and the password you has been put when requested

Click on System --> Inputs --> Syslog UDP --> Launch New Input --> Title ( ex Graylog2 ) --> Port 10514 --> Lunch

You will be able now to start to analyze logs

License
----

MIT


**Free Software, Hell Yeah!**

[@thomasfuchs]:http://twitter.com/Simone_Arena
[GitHub]:https://github.com/SimoneArena
[Email]:simone.arena@tutanota.de
