# Installed as /etc/bash/hyp-welcome.sh: Alpine's /etc/bash/bashrc sources
# /etc/bash/*.sh for every interactive bash. Prints demo-help once per shell
# tree; non-interactive runs (docker exec <c> interop.sh, one-shot modes) stay
# quiet.
case $- in
*i*)
    if [ -z "${HYP_WELCOMED:-}" ] && command -v demo-help >/dev/null 2>&1; then
        export HYP_WELCOMED=1
        demo-help
    fi
    ;;
esac
