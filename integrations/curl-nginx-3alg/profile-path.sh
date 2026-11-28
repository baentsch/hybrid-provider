# Installed as /etc/profile.d/hyp-path.sh. /etc/profile resets PATH for login
# shells (bash -l); put the demo's tools back so a login shell works like a
# plain one.
export PATH="/opt/pq/bin:/opt/nginx/sbin:${PATH}"
