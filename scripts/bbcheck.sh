#!/bin/sh
# Diagnoses Bitbucket credentials without ever printing them: shows which
# variables are set, their shape, and the HTTP status of the three kinds of
# call skarvel makes.
#   scripts/bbcheck.sh [workspace]      (default workspace: bloxbits)
ws="${1:-bloxbits}"
api=https://api.bitbucket.org/2.0

shape() { # name value
	if [ -z "$2" ]; then echo "  $1: not set"; return; fi
	trimmed=$(printf '%s' "$2" | tr -d ' \t\r\n')
	note=""
	[ "$trimmed" != "$2" ] && note="$note, CONTAINS WHITESPACE/NEWLINE"
	case "$2" in \"* | *\" | \'* | *\') note="$note, WRAPPED IN QUOTES" ;; esac
	echo "  $1: set, ${#2} chars, starts with '$(printf '%.5s' "$2")'$note"
}

echo "variables:"
shape BITBUCKET_USER "$BITBUCKET_USER"
[ -n "$BITBUCKET_USER" ] && case "$BITBUCKET_USER" in
	*@*) echo "    (looks like an email: correct for API tokens)" ;;
	*) echo "    (NOT an email: API tokens need your Atlassian account email here)" ;;
esac
shape BITBUCKET_APP_PASSWORD "$BITBUCKET_APP_PASSWORD"
shape BITBUCKET_TOKEN "$BITBUCKET_TOKEN"

if [ -n "$BITBUCKET_USER" ] && [ -n "$BITBUCKET_APP_PASSWORD" ]; then
	auth="basic"
elif [ -n "$BITBUCKET_TOKEN" ]; then
	auth="bearer"
else
	auth="none"
fi
echo "auth used: $auth"
echo

call() { # label url
	tmp=$(mktemp)
	case "$auth" in
	basic) code=$(curl -s -o "$tmp" -w '%{http_code}' -u "$BITBUCKET_USER:$BITBUCKET_APP_PASSWORD" "$2") ;;
	bearer) code=$(curl -s -o "$tmp" -w '%{http_code}' -H "Authorization: Bearer $BITBUCKET_TOKEN" "$2") ;;
	*) code=$(curl -s -o "$tmp" -w '%{http_code}' "$2") ;;
	esac
	msg=$(grep -o '"message": *"[^"]*"' "$tmp" | head -1)
	echo "  $code  $1 ${msg:+ $msg}"
	rm -f "$tmp"
}

echo "calls:"
call "who am I (/user)               " "$api/user"
call "list workspace repos (preflight)" "$api/repositories/$ws?pagelen=1"
call "code search                     " "$api/workspaces/$ws/search/code?search_query=codeprettier.pro&pagelen=1"
