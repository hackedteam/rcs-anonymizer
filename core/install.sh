#!/bin/sh
###
### bbproxy installer
###

echo -n "Installing bbproxy"

if [ `whoami` != "root" ]; then
   echo -e "\n[E] You must be root"
   exit 1
fi

echo -n "."

if [ -x /etc/init.d/bbproxy ]; then
   /etc/init.d/bbproxy stop
elif [ -x /opt/bbproxy/init.d/bbproxy ]; then
   /opt/bbproxy/init.d/bbproxy stop
fi

echo -n "."

if ! tail -n +80 "$0" | tar xz -C /opt/; then
   echo -e "\n[E] Unable to extract the tarball"
   exit 1;
fi

echo -n "."

if [ `uname -m` == 'x86_64' ]; then
   arch=64
else
   arch=32
fi

if ! ln -sf bbproxy$arch /opt/bbproxy/bbproxy; then
   echo -e "\n[E] Unable to create symlink"
   exit 1;
fi


if ! mkdir -p /opt/bbproxy/tmp/; then
   echo -e "\n[E] Unable to create tmp"
   exit 1;
fi

for n in 4 6; do
   if fuser -$n -s 80/tcp; then
      echo -e "\n[E] The following processes must be terminated before installation"
      fuser -$n -v 80/tcp
      exit 1
   fi
done

echo -n "."

if [ -d /etc/init.d ]; then
   cp /opt/bbproxy/init.d/bbproxy /etc/init.d/bbproxy
   chmod 0755 /etc/init.d/bbproxy
   
   if chkconfig --add bbproxy >/dev/null 2>&1; then true
   elif update-rc.d bbproxy defaults >/dev/null 2>&1; then true
   else echo -e "\n[W] The distribution is not supported, you must run \"/etc/init.d/bbproxy start\" manually at boot"
   fi

   /etc/init.d/bbproxy start
else
   echo -e "\n[W] The distribution is not supported, you must run \"/opt/bbproxy/init.d/bbproxy start\" manually at boot"

   /opt/bbproxy/init.d/bbproxy start
fi

echo "."

echo "Installation completed"

exit 0

#EOF
