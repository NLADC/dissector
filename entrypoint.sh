#!/usr/bin/env bash
if [ -z "${DISSECTOR_DOCKER}" ]; then
    echo "This script is ONLY for use within a Docker container"
    exit 1
fi

create_user()
{
# command > /dev/null 2>&1
  groupadd -o -g "${GID}" mygroup
  useradd -o -c "nobody" -s /usr/sbin/nologin -d /home/myuser -g "${GID}" -u "${UID}" myuser
  RUNARGS="runuser -g mygroup -u myuser --"
  mkdir /home/myuser
  chown -R myuser:mygroup /home/myuser
}

RUNARGS=""

if [ -n "${UID}" ] && [ -n "${GID}" ]; then
  # UID and GID are both set
  # Check that they are both numbers, since names have no meaning in this context:
  # We need the UID:GID numbers in this container to be the same as on the host
  if [ "${UID}" -eq "${UID}" ] 2>/dev/null; then
    # UID is a number
    if [ "${GID}" -eq "${GID}" ] 2>/dev/null; then
      # GID is a number
      # Create the user and group with these specific numbers
      create_user
    fi
  fi
fi

${RUNARGS} $@
