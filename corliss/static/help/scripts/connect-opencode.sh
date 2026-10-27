#!/usr/bin/env bash
# Connect opencode, on a machine with no browser, to SCN Notes over MCP.
#
#   curl -fsSLO https://sharedcomputer.network/static/help/scripts/connect-opencode.sh
#   bash connect-opencode.sh [--reauth] [MCP_URL]
#
# Run it as the user the agent runs as. It adds the server, sets which of its
# tools ask before they run, and signs in: open the printed link in a browser
# on any machine, click Allow, and paste back the address the browser lands
# on. Safe to run again; it changes only what is missing.
#
# Written against opencode 2.2.0. Needs curl and jq.
#
# Why each step is the way it is:
#
# - **The pasted address is checked here and delivered from a quoted
#   variable.** Pasted unquoted into bash, `…/callback?code=X&state=Y` splits
#   at the `&`: curl runs in the background without the state, and opencode
#   refuses it as "OAuth state mismatch" while the address on screen looks
#   right. That is the failure this script exists to prevent.
# - **Permissions are written to opencode.json, never opencode.jsonc.**
#   opencode loads both, and `opencode mcp add` writes plain JSON to
#   opencode.json, so the file edited here is one jq can parse. If someone has
#   put comments in it, the script stops and prints the rules to add by hand
#   rather than rewrite a file it cannot read faithfully.
# - **Nothing pasted is echoed or logged.** The one place it appears outside
#   this process is the curl that delivers it, whose arguments the same user
#   can see in `ps` for the moment it runs.

set -euo pipefail

NAME=scnnotes
MCP_URL=https://mcp.sharedcomputer.network
REAUTH=0
# Every other tool asks first. These only read.
READ_ONLY_TOOLS=(list_vaults list_notes read_note search_notes)

say() { printf '%s\n' "$*"; }
die() {
	printf 'connect-opencode: %s\n' "$*" >&2
	exit 1
}

for arg in "$@"; do
	case $arg in
	--reauth) REAUTH=1 ;;
	https://*) MCP_URL=${arg%/} ;;
	*) die "usage: bash connect-opencode.sh [--reauth] [MCP_URL]" ;;
	esac
done

auth_pid=
log=
tmp=
cleanup() {
	if [[ -n $auth_pid ]]; then kill "$auth_pid" 2>/dev/null || true; fi
	if [[ -n $tmp ]]; then rm -f "$tmp"; fi
	if [[ -n $log ]]; then rm -f "$log"; fi
}
trap cleanup EXIT

# The value of one parameter in a query string, raw, or nothing.
param() {
	local -a pairs
	local pair
	IFS='&' read -ra pairs <<<"$2"
	for pair in "${pairs[@]}"; do
		if [[ ${pair%%=*} == "$1" ]]; then
			printf '%s' "${pair#*=}"
			return 0
		fi
	done
}

urldecode() {
	local s=${1//+/ }
	printf '%b' "${s//%/\\x}"
}

# --- Preflight --------------------------------------------------------------

command -v opencode >/dev/null || die "opencode is not on PATH for $(id -un)."
for tool in curl jq; do
	command -v "$tool" >/dev/null || die "$tool is not installed. On Debian: sudo apt install $tool"
done

version=$(opencode --version 2>/dev/null || true)
case $version in
*2.2.*) ;;
*) say "Note: this script was written for opencode 2.2, and this is ${version:-an unknown version}. Continuing." ;;
esac

# The server is global, so a project directory the member happens to be in
# must not change what is found.
cd "$HOME"

# --- The server -------------------------------------------------------------
#
# Read from opencode's resolved config, which is JSON whatever the files are,
# so a commented opencode.jsonc does not get in the way of finding it.

config=$(opencode debug config) ||
	die "opencode could not read its configuration. Run 'opencode debug config' to see why."

current=$(jq -r --arg n "$NAME" '
	[.. | objects | .mcp? | objects | .servers? | objects | .[$n]? | objects | .url? // empty]
	| last // empty' <<<"$config")

if [[ -z $current ]]; then
	opencode mcp add "$NAME" --global --url "$MCP_URL" >/dev/null
	say "Added $NAME ($MCP_URL)."
elif [[ ${current%/} != "$MCP_URL" ]]; then
	die "$NAME is already set up for $current, not $MCP_URL. Remove it from your opencode config, or pass that address to this script."
else
	say "$NAME is already set up."
fi

# --- Permissions ------------------------------------------------------------
#
# opencode 2.2 keeps an ordered `permissions` list and the last rule that
# matches wins, so the catch-all ask goes first and the read-only allows after
# it. An MCP tool's action is `<server>_<tool>`.

rules=$(jq -nc --arg n "$NAME" --args '
	[{action: ($n + "_*"), resource: "*", effect: "ask"}]
	+ [$ARGS.positional[] | {action: ($n + "_" + .), resource: "*", effect: "allow"}]' \
	"${READ_ONLY_TOOLS[@]}")

config_dir=${XDG_CONFIG_HOME:-$HOME/.config}/opencode
file=$config_dir/opencode.json

if [[ -e $file ]] && ! jq -e 'type == "object"' "$file" >/dev/null 2>&1; then
	present=$(jq --argjson rules "$rules" '
		[.. | objects | .permissions? | arrays | .[]] as $all
		| $rules | all(. as $r | $all | any(. == $r))' <<<"$config")
	if [[ $present != true ]]; then
		say "$file has comments or other JSONC in it, so this script will not rewrite it."
		say "Add these to the end of its \"permissions\" list, then run this script again:"
		jq . <<<"$rules"
		exit 1
	fi
	say "Permission rules are already in place."
else
	before='{}'
	if [[ -e $file ]]; then before=$(<"$file"); fi
	# Any earlier rule for these five actions is replaced, so they end up
	# last and in order. Every other rule is kept where it was.
	updated=$(jq --argjson rules "$rules" '
		($rules | map(.action)) as $ours
		| .permissions = ([(.permissions // [])[] | select(.action as $a | $ours | any(. == $a) | not)] + $rules)' \
		<<<"$before")
	if jq -e --argjson after "$updated" '. == $after' <<<"$before" >/dev/null; then
		say "Permission rules are already in place."
	else
		mkdir -p "$config_dir"
		tmp=$(mktemp "$config_dir/.opencode.json.XXXXXX")
		printf '%s\n' "$updated" >"$tmp"
		if [[ -e $file ]]; then chmod --reference="$file" "$tmp"; else chmod 644 "$tmp"; fi
		mv -f "$tmp" "$file"
		tmp=
		say "Set $NAME's tools to ask first, except ${READ_ONLY_TOOLS[*]}."
	fi
fi

# --- Sign in ----------------------------------------------------------------

state_of() { opencode mcp list 2>/dev/null | awk -v n="$NAME" '$2 == n { print $3 }'; }

if [[ $(state_of) == connected && $REAUTH == 0 ]]; then
	say "$NAME is already signed in and connected. Run with --reauth to sign in again."
	exit 0
fi

# With no terminal on its input or output, opencode opens no browser and asks
# no questions: it prints the sign-in address and waits on a local port.
log=$(mktemp)
NO_COLOR=1 opencode mcp auth "$NAME" </dev/null >"$log" 2>&1 &
auth_pid=$!

authorize_url=
for _ in $(seq 60); do
	authorize_url=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -o 'https://[^[:space:]]*[?&]state=[^[:space:]]*' | head -n 1 || true)
	if [[ -n $authorize_url ]] || ! kill -0 "$auth_pid" 2>/dev/null; then break; fi
	sleep 0.5
done
if [[ -z $authorize_url ]]; then
	say "opencode did not start the sign-in. It said:" >&2
	tail -n 5 "$log" >&2
	exit 1
fi

query=${authorize_url#*\?}
expected_state=$(param state "$query")
redirect=$(urldecode "$(param redirect_uri "$query")")
[[ $redirect =~ ^http://127\.0\.0\.1:([0-9]+)/callback$ ]] ||
	die "opencode is waiting at $redirect, which this script does not know how to reach."
port=${BASH_REMATCH[1]}

say ""
say "Open this link in a browser on any machine and sign in:"
# The link's text is the address itself, so a terminal without OSC 8 links
# shows the plain address and nothing that looks like a heading.
if [[ -t 1 ]]; then
	printf '\e]8;;%s\e\\%s\e]8;;\e\\\n\n' "$authorize_url" "$authorize_url"
else
	say "$authorize_url"
	say ""
fi

# Why a paste is refused, in words, without repeating any of it. Returns 2 for
# an answer that ends this sign-in, 1 for a paste worth trying again.
reason=
check() {
	local url=$1 query error
	if [[ ! $url =~ ^http://127\.0\.0\.1:([0-9]+)/callback\?(.+)$ ]]; then
		reason="That is not where a finished sign-in lands. Copy the whole address; it starts http://127.0.0.1:$port/callback?"
		return 1
	fi
	query=${BASH_REMATCH[2]}
	if [[ ${BASH_REMATCH[1]} != "$port" ]]; then
		reason="That address is from an older sign-in. Use the tab opened from the link above."
		return 1
	fi
	error=$(param error "$query")
	if [[ -n $error ]]; then
		if [[ $error == access_denied ]]; then
			reason="The sign-in was cancelled."
		else
			reason="The sign-in failed: $(urldecode "$(param error_description "$query")") ($error)."
		fi
		return 2
	fi
	if [[ -z $(param state "$query") ]]; then
		reason="That address is cut short: the part after the & is missing. Copy the whole address from the browser."
		return 1
	fi
	if [[ $(param state "$query") != "$expected_state" ]]; then
		reason="That address is from a different sign-in attempt. Use the tab opened from the link above."
		return 1
	fi
	if [[ -z $(param code "$query") ]]; then
		reason="That address has no sign-in code in it. Copy the whole address from the browser."
		return 1
	fi
}

# Read the paste without showing it, but say as soon as something arrived:
# with no sign of it, the natural thing is to paste again, and two copies run
# together are no address at all.
read_paste() {
	local c
	pasted=
	printf '%s' "Click Allow, then paste the address your browser lands on: "
	while IFS= read -rs -n 1 c </dev/tty; do
		if [[ -z $c ]]; then break; fi
		if [[ $c == $'\x7f' || $c == $'\b' ]]; then
			pasted=${pasted%?}
			continue
		fi
		if [[ -z $pasted ]]; then printf '%s' "(received, press Enter)"; fi
		pasted+=$c
	done
	printf '\n'
}

while :; do
	read_paste
	pasted=${pasted//[[:space:]]/}
	if [[ -z $pasted ]]; then continue; fi
	# A code or state never contains a colon, so two of these is two pastes.
	if [[ ${pasted#*://} == *://* ]]; then
		say "That looks like the address pasted more than once. Paste it once, then press Enter."
		continue
	fi
	# Some browsers copy the address without its scheme.
	if [[ $pasted == 127.0.0.1:* ]]; then pasted=http://$pasted; fi
	kill -0 "$auth_pid" 2>/dev/null || die "opencode stopped waiting for the sign-in. Run this script again."
	if check "$pasted"; then break; else outcome=$?; fi
	if [[ $outcome == 2 ]]; then die "$reason"; fi
	say "$reason"
done

# opencode answers once it has traded the code for tokens, so this returns
# when the sign-in has finished either way.
curl -sS -o /dev/null --max-time 60 "$pasted" || true
pasted=

if wait "$auth_pid"; then
	auth_pid=
else
	auth_pid=
	failure=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -m 1 '■' | sed 's/^[^[:alnum:]]*//; s/\(code\|state\)=[^&[:space:]]*/\1=…/g' || true)
	die "opencode could not finish the sign-in: ${failure:-no reason given}."
fi

if [[ $(state_of) == connected ]]; then
	say "Connected. Your agent can now reach SCN Notes as $NAME."
else
	line=$(opencode mcp list 2>/dev/null | awk -v n="$NAME" '$2 == n' || true)
	die "signed in, but opencode reports: ${line:-$NAME is not listed}"
fi
