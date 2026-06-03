# Put the ARK-OS operator scripts on PATH for login shells. Each script's shebang
# points at the bundled venv (/usr/lib/ark-os/venv/bin/python3), so they run with
# nothing to activate -- e.g. `mavlink_shell.py`, `flash_firmware.sh`.
case ":${PATH}:" in
    *:/usr/lib/ark-os/scripts:*) ;;
    *) PATH="${PATH}:/usr/lib/ark-os/scripts" ;;
esac

# Dev/diagnostic extras (jetson) live in their own subdir but are still on PATH.
case ":${PATH}:" in
    *:/usr/lib/ark-os/scripts/extras:*) ;;
    *) PATH="${PATH}:/usr/lib/ark-os/scripts/extras" ;;
esac
